## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `ec590a08cd..386792876d`

The change replaces the CLI's plain `BEGIN; <EQL bundle>; COMMIT` reinstall (which silently cascade-dropped every customer object depending on eql_v3, e.g. functional search indexes) with a protocol that, in one transaction under an advisory lock, walks pg_depend for external dependants of the EQL schemas, refuses before mutation if any are not plain standalone indexes, runs the bundle, then recreates the captured indexes from pg_get_indexdef and verifies definition, validity, clustering, replica identity, comment, owner and statistics targets. It also refactors status/verify/preflight onto a single read-only `assessEqlInstallation` snapshot. This is a net safety improvement for customer data at rest, but it is a customer-facing change to `stash eql install --force` and `stash eql upgrade`: (1) the index rebuild now happens while DROP SCHEMA ... CASCADE holds ACCESS EXCLUSIVE locks on every affected customer table, so tables are unavailable for the full rebuild duration; (2) catalog properties pg_get_indexdef does not carry (exclusion-constraint ownership, tablespace) are not captured or verified, so an exclusion constraint over an EQL term expression can plausibly come back as a plain index with verification passing; (3) databases with views, policies, check constraints or partitioned indexes over EQL, which previously upgraded (losing those objects), now exit 1. Extensive live Postgres tests exist but none were run here and no CI results were provided.

### Failure scenarios

**FS-1 · Exclusion constraint over an EQL term is silently rebuilt as a plain index** (high impact, plausible)

- Trigger: A customer table has `EXCLUDE USING btree (eql_v3.eq_term(col) WITH =)` (or similar) and the operator runs `stash eql upgrade` / `install --force`.
- Mechanism: eq_term returns eql_v3_internal.hmac_256, a domain over text, so the exclusion operator is pg_catalog text `=` and the pg_constraint row has no pg_depend edge into EQL; only its index does. LIFECYCLE_DEPENDENCIES_SQL therefore classifies the backing index as kind 'index' (relkind 'i', not a partition) rather than unsafe. DROP SCHEMA CASCADE drops the index and, through its internal dependency, the owning constraint. rebuildIndexes replays pg_get_indexdef, which emits `CREATE INDEX ... USING btree (eql_v3.eq_term(col))` without exclusion semantics, and VERIFY_REBUILT_INDEXES_SQL compares only that same definition text and catalog flags, so verification passes.
- Consequence: Install reports success while the database has lost a uniqueness/exclusion guarantee on encrypted data; duplicates can be written afterwards with no error. Silent integrity loss.
- Affects: packages/cli installer (EQLInstaller.install, derived-search-index-restoration), Customer PostgreSQL databases (tables with EQL functional indexes, views/policies/constraints on EQL)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:571-651`; `packages/cli/src/installer/derived-search-index-restoration.ts:293-316`; `packages/eql/crates/eql-bindings/sql/cipherstash-encrypt.sql:14448`
- Existing verification: reinstall.live.test.ts covers unique indexes, partitioned indexes, views, policies, check constraints, generated columns, triggers and operators; no exclusion-constraint case was found. [exists_not_run]
- Missing verification: A live test with an exclusion constraint whose index expression uses an EQL function, asserting refusal or that the pg_constraint row survives.; Verification that compares pg_index.indisexclusion / constraint ownership (conindid) before and after.
- Mitigation: Classify any index with indisexclusion, indisprimary or a pg_constraint row referencing it (conindid) as unsafe, or capture and replay pg_get_constraintdef; add the constraint check to the post-rebuild verification.

**FS-2 · Customer tables locked for the whole index rebuild during upgrade** (medium impact, plausible)

- Trigger: `stash eql upgrade` on a database with large tables carrying EQL functional indexes, outside a maintenance window.
- Mechanism: The bundle's DROP SCHEMA ... CASCADE drops dependent indexes, which takes ACCESS EXCLUSIVE on their tables; the same transaction then runs non-concurrent CREATE INDEX (recomputing the EQL term function per row) and ANALYZE for every table before COMMIT. Previously the cascade dropped the indexes and committed quickly.
- Consequence: Reads and writes on every encrypted table with a search index block for the full rebuild duration (proportional to table size); an application outage, or a statement_timeout-triggered rollback that leaves the upgrade impossible to complete online. No data loss: rollback restores prior state.
- Affects: packages/cli installer (EQLInstaller.install, derived-search-index-restoration), `stash eql install --force` / `stash eql upgrade` CLI commands, Customer PostgreSQL databases (tables with EQL functional indexes, views/policies/constraints on EQL)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:678-691`; `packages/eql/crates/eql-bindings/sql/cipherstash-encrypt.sql:39-47`; `packages/cli/README.md:220-222`
- Existing verification: Live tests exercise rebuild on small fixture tables only; no timing or lock test. [exists_not_run]
- Missing verification: A measurement of rebuild duration and lock hold time at representative row counts.
- Mitigation: Docs already say to run upgrade in a maintenance window; state explicitly in the CLI output/README that affected tables are locked for the rebuild, and consider printing the list and sizes of indexes to be rebuilt (e.g. in --dry-run) before mutating.

**FS-3 · Upgrades that previously succeeded now exit 1 for databases with views, policies or partitioned indexes on EQL** (medium impact, plausible)

- Trigger: A customer database has an RLS policy, view, check constraint, generated column or partitioned-table index referencing EQL functions and runs `stash eql upgrade` (possibly in automation).
- Mechanism: inspectReinstallDependencies throws EqlReinstallRefusalError for any non-index dependant, and partitioned/attached indexes are classified unsafe; install.ts/upgrade.ts map it to CliExit(1).
- Consequence: Upgrade is blocked until the operator removes and recreates those objects manually; deploy pipelines that run upgrade fail. Loud and recoverable, and preferable to the old silent cascade-drop, but a contract change. Customers with partitioned encrypted tables have no CLI upgrade path.
- Affects: `stash eql install --force` / `stash eql upgrade` CLI commands, Automation that runs `stash eql upgrade` non-interactively (deploy scripts, CI)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:293-316`; `packages/cli/src/commands/db/upgrade.ts:53-65`; `packages/cli/src/installer/derived-search-index-restoration.ts:552-556`
- Existing verification: reinstall.live.test.ts asserts refusal before mutation for each listed dependency kind and for partitioned index trees. [exists_not_run]
- Missing verification: Documented manual procedure for upgrading a database whose dependants are refused (e.g. partitioned tables).
- Mitigation: Call out the new refusal in the changeset/release notes as a behaviour change, and document the drop/recreate procedure; ensure --dry-run reports refusals without mutating.

**FS-4 · Rebuilt index silently moves to the default tablespace** (low impact, plausible)

- Trigger: An EQL functional index lives in a non-default tablespace.
- Mechanism: pg_get_indexdef(oid) does not emit a TABLESPACE clause and neither the capture nor VERIFY_REBUILT_INDEXES_SQL reads reltablespace, so the rebuilt index is created in default_tablespace and verification passes.
- Consequence: Storage placement changes without notice; the default tablespace may fill (rebuild then fails and rolls back) or performance characteristics change.
- Affects: packages/cli installer (EQLInstaller.install, derived-search-index-restoration), Customer PostgreSQL databases (tables with EQL functional indexes, views/policies/constraints on EQL)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:571-651`; `packages/cli/src/installer/derived-search-index-restoration.ts:293-316`
- Missing verification: A live test with an index in a non-default tablespace.
- Mitigation: Capture reltablespace and append TABLESPACE to the replayed definition (or refuse), and include it in verification.

### Recommended controls

- Add live tests: exclusion constraint on eql_v3.eq_term(col) and an index in a non-default tablespace; assert refusal or faithful restoration. (test; FS-1, FS-4, VG-1)
- Review LIFECYCLE_DEPENDENCIES_SQL's index classification against pg_index flags (indisexclusion, indisprimary, indisunique with conindid) and pg_constraint.conindid. (review_focus; FS-1)
- Release notes: state that upgrade now refuses on views/policies/partitioned indexes and that affected tables are ACCESS EXCLUSIVE locked during rebuild; give the manual procedure. (documentation; FS-2, FS-3)
- Confirm the CI run for the head commit (both PG16 and PG17 legs, including the credentialed upgrade-encrypted-indexes suite) passed before release. (compatibility_check; VG-2)

### What this assessment could not see

- No PostgreSQL server or node_modules were available, so no tests were run and the FS-1/FS-4 catalog behaviour (pg_get_indexdef output for exclusion indexes, cascade through internal dependencies) is from knowledge of PostgreSQL, not observed. FS-1 and FS-4 are plausible_failure rather than observed_defect.
- Test files (installer.test.ts, installation-state.test.ts, verify.test.ts, reinstall.live.test.ts) were skimmed for case names, not read in full; validate.ts and lint script refactors were read only at diff level; the Rust sqlx uninstall test was not read. Coverage claims are based on test names; a scenario might be covered under a different name.
- No PR description, CI results or deployment context were provided. Cannot confirm test outcomes or how customers run upgrade in practice.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
