## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `ec590a08cd..386792876d`

Before this change, `stash eql install` and `stash eql upgrade` ran the EQL bundle in one transaction. The bundle's `DROP SCHEMA eql_v3/eql_v3_internal CASCADE` silently dropped customer functional indexes, and any views, policies or constraints, that depended on EQL. The new code takes an advisory lifecycle lock and walks pg_depend to classify dependants. It refuses before mutating anything when it finds a dependant that is not an index. Otherwise it runs the bundle, rebuilds each captured index with plain CREATE INDEX, restores cluster, replica identity, comment and statistics settings, runs ANALYZE, verifies the result and commits, all in the same transaction. Installation-state reads are moved into assessEqlInstallation. The main release risk is operational, not data loss. Every CREATE INDEX and ANALYZE now runs inside the transaction that dropped the old indexes, so tables with EQL-backed indexes stay locked for the whole rebuild. Upgrades can now fail closed where they used to succeed, for example when the installer role does not own the indexed tables or the new bundle cannot rebuild an old index definition. Failures roll back, and the live tests cover rollback and the refusal classes. CI is all green, and its live-Postgres job ran on PG16 and PG17.

### Failure scenarios

**FS-1 · Upgrade blocks reads and writes on large encrypted tables while every captured index is rebuilt inside one transaction** (high impact, plausible)

- Trigger: An operator runs `stash eql upgrade` (or `install --force`) against a production database with large tables that carry EQL functional indexes, outside a maintenance window. The README previously called the install SQL 'idempotent and safe to re-run'.
- Mechanism: The bundle's DROP SCHEMA ... CASCADE drops the dependent indexes, which takes an ACCESS EXCLUSIVE lock on each parent table. rebuildIndexes then runs each captured definition as a plain, non-CONCURRENTLY CREATE INDEX, runs ANALYZE on every table, and only then commits (derived-search-index-restoration.ts:575-598, 678-687). At base, the transaction ended right after the bundle. It now also covers a full index build per index, evaluating EQL SQL functions on every row, plus ANALYZE. All of it runs while table locks taken at the drop are still held.
- Consequence: Application queries against those tables block for the whole rebuild. On large tables that can be minutes or longer, an availability outage. If a server-side statement_timeout or lock_timeout fires, everything rolls back safely, but the upgrade cannot complete without a window.
- Affects: packages/cli installer (derived-search-index-restoration.ts, index.ts), `stash eql install` / `stash eql upgrade` commands, Customer PostgreSQL databases (tables carrying EQL-backed functional indexes)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:678-691`; `packages/eql/packages/eql/sql/cipherstash-encrypt.sql:39-47`; `packages/cli/src/installer/derived-search-index-restoration.ts:571-651`; `packages/cli/README.md:213-222`
- Existing verification: The live reinstall suite rebuilds indexes on single-row tables only. It covers correctness, not duration or locking. [exists_not_run]; The CI jobs 'Run Tests (Node 22)' and 'Run Tests (Node 24)' that run the CLI live suites passed. [ran_passed]
- Missing verification: No measurement of lock duration or rebuild time on a table of realistic size; No dry-run or preflight output that tells the operator how many indexes and tables will be rebuilt and locked
- Mitigation: Already present: README and SKILL.md now say to run upgrade in a maintenance window. Consider having `upgrade --dry-run` list the indexes and tables that will be rebuilt and locked, and put the lock warning in the CLI output itself.

**FS-2 · Upgrade now fails, where it used to succeed, when the installer role does not own the indexed customer tables** (medium impact, plausible)

- Trigger: The installer connects as a role that owns, or is a member of the owner of, the EQL schemas, but does not own the application tables carrying EQL-backed indexes. Examples are a dedicated migration or admin role on managed Postgres, or tables owned by an app role.
- Mechanism: DROP ... CASCADE removes dependent objects without checking ownership of each one, so at base the upgrade succeeded and silently dropped the indexes. At head, rebuildIndexes runs CREATE INDEX on the customer table, and PostgreSQL requires table ownership for that. The failure becomes DerivedSearchIndexReconstructionError and is wrapped as 'Failed to install EQL ... rolled back' (index.ts:196-213). Preflight checks only that the role can drop the EQL schemas, not that it owns the dependent tables (installation-state.ts:66-76, 228-231).
- Consequence: The upgrade fails closed after doing the work and rolls back, and is shown as a generic thrown error rather than a refusal. The customer cannot upgrade EQL with that role until they change roles or drop the indexes. No data is lost.
- Affects: packages/cli installer (derived-search-index-restoration.ts, index.ts), `stash eql install` / `stash eql upgrade` commands, Customer PostgreSQL databases (tables carrying EQL-backed functional indexes), EQLInstaller programmatic API (documented in packages/cli/README.md)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:571-651`; `packages/cli/src/installer/index.ts:194-214`; `packages/cli/src/installer/installation-state.ts:66-186`; `packages/cli/src/installer/__tests__/reinstall.live.test.ts:188-209`
- Existing verification: The live test 'preserves index ownership' runs as the superuser `cipherstash`, so the non-owner path is not exercised. [exists_not_run]
- Missing verification: A live test where the installer role owns the EQL schemas but not the table carrying the dependent index; A preflight check of ownership of dependent tables, so the refusal happens before mutation and with a clear message
- Mitigation: Add an ownership check in inspectReinstallDependencies (or preflight) that refuses with EqlReinstallRefusalError and names the table, before the bundle runs.

**FS-3 · An upgrade that changes or removes an EQL function used by an existing index can no longer complete** (medium impact, plausible)

- Trigger: A future pinned bundle removes, renames or changes the signature or return type of a function (for example eql_v3.eq_term) that a customer index expression references, or changes how pg_get_indexdef prints the rebuilt definition.
- Mechanism: The rebuild replays the captured CREATE INDEX text verbatim. Verification also requires the new pg_get_indexdef output to be byte-identical to the captured text (derived-search-index-restoration.ts:612-637). Any change to the bundle surface used by an index expression either fails the CREATE or fails verification, and either one rolls back the whole upgrade.
- Consequence: The customer is stuck on the old EQL version until they manually drop and recreate the affected indexes around the upgrade. This is loud and safe, but it shifts a migration burden onto future EQL releases and onto customers.
- Affects: packages/cli installer (derived-search-index-restoration.ts, index.ts), `stash eql install` / `stash eql upgrade` commands, Customer PostgreSQL databases (tables carrying EQL-backed functional indexes)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:571-651`; `packages/cli/src/installer/__tests__/upgrade-encrypted-indexes.live.test.ts:23-43`
- Existing verification: upgrade-encrypted-indexes.live.test.ts upgrades from the released 3.0.2 bundle to the pinned bundle with real ciphertext and unique and ORE indexes. It is gated on CS_* credentials, and whether it ran in CI is not visible. [unknown]
- Missing verification: A release-time check that each EQL function referenced by documented index recipes survives a bundle bump with the same signature
- Mitigation: Treat removal or signature change of index-referenced EQL functions as a breaking EQL change in the release process, and document the manual recovery path in the reconstruction error message.

### Recommended controls

- Review rebuildIndexes and the transaction body in restoreDerivedSearchIndexesAroundEqlReplacement for lock scope, and decide whether the CLI should warn about or list the tables that will be locked before it proceeds. (review_focus; FS-1, VG-1)
- Add a live test that installs EQL as a non-superuser role that owns the EQL schemas but not a table with a dependent index, and assert that the command refuses before mutation with a clear message. (test; FS-2, VG-2)
- Release notes should say that `stash eql upgrade` now holds locks on tables with EQL indexes for the full rebuild, and that it can fail closed where it previously succeeded. (documentation; FS-1, FS-2, FS-3)
- Confirm from the CI logs that upgrade-encrypted-indexes.live.test.ts ran rather than being skipped, on both PG16 and PG17. (compatibility_check; VG-3, FS-3)

### What this assessment could not see

- LIFECYCLE_DEPENDENCIES_SQL was read in full, but whether its classification is complete across every catalog edge (for example a constraint that owns an index built on an EQL opclass) was reasoned about, not executed. The refusal classes the live tests cover were checked by name only. A dependant that is misclassified as a rebuildable index could still be lost silently. That risk was judged low but not proven.
- The test, refactor and docs files (installer.test.ts, verify.ts, validate.ts, grants.ts, the sqlx uninstall tests, lint scripts) were skimmed, not read closely. Behaviour changes in the assessment refactor (status, verify, validate) are only partly checked.
- Concurrent DDL from sessions other than `stash` between dependency capture and the bundle's DROP is not covered by the advisory lock. An index created in that gap would be dropped without being rebuilt. The README documents this as a maintenance-window requirement. Not raised as a scenario because the change documents it, and the same exposure existed at base.
- No tests were run locally (no database, no network). Test results come only from ci.json conclusions. Verification confidence is capped at medium.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
