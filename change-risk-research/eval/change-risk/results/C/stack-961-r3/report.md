## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `ec590a08cd..386792876d`

Replaces the CLI's plain 'run the EQL bundle in a transaction' install/upgrade with a protocol that, in one transaction, takes an advisory lifecycle lock, walks pg_depend for customer objects that depend on the disposable eql_v3/eql_v3_internal schemas, refuses before mutation if any is not a plain index, runs the bundle (DROP SCHEMA ... CASCADE), rebuilds and verifies the captured indexes and ANALYZEs their tables. It also centralises read-only installation assessment. Versus base this is a large safety improvement: base silently cascade-dropped dependent indexes, views and policies. The data-integrity paths (rollback after DROP, refusal before mutation, upgrade from released 3.0.2 with real ciphertext) have live tests in CI jobs that passed, though per-test results were not visible. The residual release risks are operational: every EQL-indexed table is now locked for the time it takes to rebuild and analyse its indexes inside the transaction (high impact on large production tables, documented only as a generic maintenance window); the rebuild needs table ownership, which the old cascade-drop did not, so non-owner install roles now fail and roll back; previously succeeding upgrades with views/policies now refuse; and the dependency walk exempts any public operator or cast built on an EQL function, so such customer objects are still dropped silently.

### Failure scenarios

**FS-1 · Upgrade locks every EQL-indexed production table for the duration of index rebuilds and ANALYZE** (high impact, plausible)

- Trigger: An operator runs stash eql upgrade (or install --force) against a database with large tables carrying EQL functional indexes, expecting a bundle swap of roughly the old duration (the code comment puts the bundle alone at 10-30 s locally).
- Mechanism: The bundle's DROP SCHEMA ... CASCADE drops each dependent index, which takes ACCESS EXCLUSIVE on its table and holds it until COMMIT (E-24). The same transaction then rebuilds every captured index with a non-concurrent CREATE INDEX evaluating an EQL function per row, applies settings and ANALYZEs each table before committing (E-1, E-2). At base the transaction ended after the bundle (E-7). No statement_timeout or lock_timeout bounds the work and nothing estimates or reports table size beforehand.
- Consequence: All reads and writes to those tables block for the full rebuild time (minutes to hours on large tables), an application outage; aborting rolls everything back and the work must be repeated.
- Affects: packages/cli installer (derived-search-index-restoration, index, installation-state, verify), Customer PostgreSQL databases with EQL-dependent indexes and objects
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:659-695`; `packages/cli/src/installer/derived-search-index-restoration.ts:571-598`; `packages/cli/src/installer/derived-search-index-restoration.ts:7-27`; `packages/cli/src/installer/index.ts:434-462` (base); `packages/cli/README.md:213-222`; `packages/cli/src/installer/derived-search-index-restoration.ts:575-598` (inferred)
- Existing verification: Live tests exercise rebuild correctness on small fixture tables only. [exists_not_run]
- Missing verification: Any measurement of lock duration or rebuild time on a populated table; Pre-flight report of which tables/indexes will be locked and rebuilt
- Mitigation: Have install/upgrade (and --dry-run) list the indexes and table sizes that will be rebuilt and require confirmation; state explicitly in README/skill that the tables are unavailable for the rebuild; consider an opt-in lock_timeout so a queued DROP does not stall all traffic.

**FS-2 · Install role that does not own the indexed tables can no longer reinstall or upgrade** (medium impact, plausible)

- Trigger: The CLI connects as a role that owns (or is a member of the owner of) the EQL schemas but not the application tables carrying EQL indexes, e.g. a dedicated migration role or a managed-platform admin role.
- Mechanism: At base, CASCADE dropped dependent indexes without ownership checks (E-7, E-24). Now rebuildIndexes issues CREATE INDEX and ALTER TABLE ... CLUSTER ON/REPLICA IDENTITY, which need table ownership (E-2, E-24). The failure surfaces as DerivedSearchIndexReconstructionError after the DROP, and the transaction rolls back. Preflight only checks schema-drop rights (E-21). The live suite runs as the CI superuser that owns everything (E-11, E-17).
- Consequence: Upgrades that previously succeeded (while losing indexes) now fail after doing the expensive part of the work; the database is left on the old EQL, so a CLI/SQL version skew persists until the operator obtains table ownership.
- Affects: packages/cli installer (derived-search-index-restoration, index, installation-state, verify), stash eql install / eql upgrade / eql status / eql verify commands, Customer PostgreSQL databases with EQL-dependent indexes and objects
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:571-598`; `packages/cli/src/installer/index.ts:434-462` (base); `packages/cli/src/installer/__tests__/reinstall.live.test.ts:188-210`; `.github/workflows/tests.yml:50-80`; `packages/cli/src/installer/installation-state.ts:78-186`; `packages/cli/src/installer/derived-search-index-restoration.ts:575-598` (inferred)
- Existing verification: Rollback after a failure post-DROP is live-tested, so a failed rebuild should leave the prior install intact. [exists_not_run]
- Missing verification: A live test installing as a non-superuser that does not own the indexed table; A preflight check of table ownership for captured indexes
- Mitigation: Add table-ownership to the dependency inventory and refuse before mutation with a named remedy; add a non-owner live test.

**FS-3 · Customer operator or cast in public built on an EQL function is still silently dropped** (medium impact, plausible)

- Trigger: A customer has created an operator in schema public (or any cast) whose implementing function lives in eql_v3/eql_v3_internal.
- Mechanism: The walk exempts any public operator whose oprcode is in an EQL schema and any cast whose castfunc is in an EQL schema, classifying them as bundle-owned from the installed catalog (E-5). The bundle's CASCADE then drops them, and the incoming bundle only recreates its own. The live suite asserts a cast built that way is exempted, and covers customer operators only in a non-public schema (E-12).
- Consequence: A customer object disappears without a refusal, contrary to the release note that unsupported dependencies are named and refused; queries using it then fail. Not a regression versus base, which dropped it too.
- Affects: packages/cli installer (derived-search-index-restoration, index, installation-state, verify), Customer PostgreSQL databases with EQL-dependent indexes and objects
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:239-273`; `packages/cli/src/installer/__tests__/reinstall.live.test.ts:274-311`; `.changeset/safe-eql-reinstall.md:1-20`
- Existing verification: Refusal table covers customer operators in a non-public schema. [exists_not_run]
- Missing verification: A case for a customer operator in public, or a customer cast, over an EQL function
- Mitigation: Compare exempted operators/casts against the set the installed bundle version created (e.g. its expected surface) rather than exempting by implementation namespace, or document the gap.

**FS-4 · Upgrades with views, policies or generated columns over EQL now refuse with no supported path forward** (medium impact, plausible)

- Trigger: A customer database has an RLS policy, view, constraint, trigger or generated column referencing EQL functions, and runs stash eql upgrade after updating the CLI.
- Mechanism: inspectReinstallDependencies refuses any non-index dependant (E-4); install/upgrade exit 1 (E-8). --dry-run returns before the inventory so the refusal is only discovered on the real run (E-9). The documented alternative for migrations is to recreate dependants manually (E-20).
- Consequence: The database stays on the older EQL while the CLI/client move on; operators may fall back to raw `eql migration` SQL, which still cascade-drops the dependants silently.
- Affects: stash eql install / eql upgrade / eql status / eql verify commands, Customer PostgreSQL databases with EQL-dependent indexes and objects, Published stash CLI npm package and bundled stash-cli agent skill
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:494-558`; `packages/cli/src/commands/db/install.ts:204-216`; `packages/cli/src/commands/db/upgrade.ts:40-63`; `skills/stash-cli/SKILL.md:499-512`
- Existing verification: Refusal before mutation for each listed kind is live-tested. [exists_not_run]
- Missing verification: Dry-run coverage of the dependency inventory
- Mitigation: Run the dependency inventory in --dry-run and print the refusal list; document a drop/recreate procedure for each refused kind.

### Recommended controls

- Review rebuildIndexes/restoreDerivedSearchIndexesAroundEqlReplacement for lock scope: confirm the team accepts a full-table lock for rebuild + ANALYZE inside the transaction, and decide on lock_timeout/statement_timeout policy. (review_focus; FS-1)
- State in README, shipped skill and release notes that EQL-indexed tables are unavailable while indexes rebuild, and that the install role must own those tables. (documentation; FS-1, FS-2)
- Add a live test that installs as a non-superuser owning the EQL schemas but not the indexed table, expecting a pre-mutation refusal. (test; FS-2, VG-2)
- Add live cases for a customer operator in public and a customer cast over an EQL function. (test; FS-3, VG-3)
- Make upgrade --dry-run run the dependency inventory and print the indexes to rebuild and any refusals. (other; FS-1, FS-4)
- Confirm from CI logs that reinstall.live and upgrade-encrypted-indexes.live executed (not skipped) on both PG16 and PG17 legs. (monitoring; VG-4)

### What this assessment could not see

- Read closely: derived-search-index-restoration.ts, installer/index.ts, installation-state.ts, verify.ts diff, install/upgrade/status/verify/validate/migration command diffs, CI/turbo/vitest changes, lint script diff. Skimmed: test files (titles and key assertions), README/skill/changeset. Not read: the ADR, packages/eql CONTEXT.md, v3_uninstall_tests.rs, unit test bodies. Scenarios in the Rust SQLx test changes or unit-test-only behaviour could be missed.
- PostgreSQL locking and ownership semantics (E-24) are from general knowledge, not verified by running PostgreSQL here. FS-1 and FS-2 mechanisms are inferred; their basis is plausible_failure, not observed_defect.
- No tests were run locally (no database or network). CI results are job-level only. Verification statuses for individual tests are exists_not_run; confidence capped at medium.
- Did not inspect the EQL v3 bundle SQL to confirm which catalog objects a real install creates (e.g. domain constraints) beyond what the live tests imply. Could not independently confirm the dependency walk produces no false refusals on every supported bundle version.
- No deployment context: customer table sizes, install roles and platforms (Supabase, RDS) unknown. Likelihood of FS-1/FS-2 cannot be judged; impact rated as if they occur.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
