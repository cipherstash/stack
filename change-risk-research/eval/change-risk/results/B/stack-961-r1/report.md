## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `ec590a08cd..386792876d`

The change replaces the CLI's EQL v3 install/upgrade (`EQLInstaller.install()`, used by `stash eql install --force` and `stash eql upgrade`) with a single-transaction protocol: take an advisory lifecycle lock, walk pg_depend for customer objects depending on the disposable eql_v3/eql_v3_internal schemas, refuse before mutation if any non-index dependant exists, run the bundle (which begins with DROP SCHEMA ... CASCADE), recreate captured functional indexes from pg_get_indexdef, restore cluster/replica-identity/comment/statistics, ANALYZE, and verify the result, rolling back on any mismatch. It also refactors installation state, preflight, status, verify and validate onto a new `assessEqlInstallation` seam. At the base the same commands silently cascade-dropped dependent indexes (and views, policies, constraints), so data-safety risk goes down. The release risks are operational. (1) Index rebuilds now run non-concurrently inside the DDL transaction, so every table with an EQL-backed index stays locked against reads and writes until commit, for a time that grows with table size. (2) Rebuilding needs table ownership, which preflight does not check, so non-owner roles that could upgrade before will now fail and roll back. (3) Upgrades that used to succeed by destroying dependent views or policies are now refused. The live-Postgres suite covers the restoration and refusal paths in depth, but I saw no run results, and it runs only as a superuser.

### Failure scenarios

**FS-1 · Upgrade locks encrypted application tables for the full index rebuild** (high impact, plausible)

- Trigger: An operator runs `stash eql upgrade` (or `eql install --force`) against a production database where large tables carry EQL functional indexes, outside a maintenance window. The base skill presented the bundle as safe to re-run.
- Mechanism: One transaction holds the lifecycle lock, runs the bundle's DROP SCHEMA ... CASCADE, which drops the dependent indexes and takes ACCESS EXCLUSIVE on their tables, then recreates each captured index with a plain, non-concurrent CREATE INDEX, then ANALYZEs each table, and only then commits (derived-search-index-restoration.ts:571-598, 679-686). The ACCESS EXCLUSIVE locks from the drops are held until commit, so reads and writes on every affected table block for the whole rebuild. At base the same transaction only dropped the indexes, so it was short.
- Consequence: Application queries on encrypted tables queue or time out for as long as the rebuild takes, which grows with table size. The result is an outage of the encrypted-data paths during what users may treat as a routine CLI upgrade. A statement_timeout or lock_timeout hit mid-rebuild rolls everything back, so the time is spent and nothing is upgraded.
- Affects: packages/cli installer (derived-search-index-restoration.ts, installer/index.ts), stash eql install --force / stash eql upgrade commands, Customer PostgreSQL databases (application tables with EQL-backed functional indexes)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:659-695`; `packages/cli/src/installer/derived-search-index-restoration.ts:571-598`; `packages/eql/packages/eql/sql/cipherstash-encrypt.sql:37-47`; `skills/stash-cli/SKILL.md:500-512`; `packages/cli/README.md:213-222`
- Existing verification: Live tests rebuild indexes on single-row fixture tables and an upgrade test with real ciphertext. None measures lock duration or concurrent-reader impact. [exists_not_run]
- Missing verification: Any measurement of rebuild and lock duration against a table of realistic size; A test or preflight output showing which tables will be locked and how big their indexes are before mutation
- Mitigation: Before mutating, print or confirm the list of tables and indexes that will be rebuilt, with their sizes. State plainly in the CLI output, README and skill that affected tables are unavailable to reads and writes until the upgrade commits. Consider a `--lock-timeout` option or a dry-run that reports the rebuild set.

**FS-2 · Upgrade by a non-owner role now fails and rolls back at index rebuild** (medium impact, plausible)

- Trigger: The role running `stash eql upgrade` owns the EQL schemas but is not a superuser and does not own (or belong to the owner of) an application table with an EQL-backed index, for example separate admin and migration roles on managed Postgres.
- Mechanism: DROP SCHEMA ... CASCADE drops dependent indexes regardless of table ownership, but the rebuild issues CREATE INDEX on the customer's table (derived-search-index-restoration.ts:575-584), and that requires table ownership. Preflight checks database/public CREATE, pgcrypto placement and EQL schema ownership, but not ownership of the tables whose indexes will be rebuilt (installation-state.ts:205-231). The failure therefore happens after the DROP, as a DerivedSearchIndexReconstructionError, and the transaction rolls back.
- Consequence: An upgrade that succeeded at base (losing indexes silently) now fails with a 'could not rebuild search index ... must be owner' error after doing most of the work. The rollback is clean, but the user is blocked from upgrading until roles are changed, and preflight never warned them.
- Affects: packages/cli installer (derived-search-index-restoration.ts, installer/index.ts), stash eql install --force / stash eql upgrade commands, Customer PostgreSQL databases (application tables with EQL-backed functional indexes)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:571-598`; `packages/cli/src/installer/installation-state.ts:188-247`; `packages/cli/src/installer/__tests__/reinstall.live.test.ts:188-209`
- Existing verification: Live reinstall tests run as the CI image's POSTGRES_USER, which owns every fixture table (asserted owner 'cipherstash'). No live test uses a non-owner installer role. [exists_not_run]
- Missing verification: Live test: installer role without ownership of an indexed table; Preflight check that the current role can CREATE INDEX on every table in the captured set
- Mitigation: Extend the pre-mutation dependency inspection to refuse, naming the tables, when the current role cannot own-rebuild a captured index. This turns a mid-transaction failure into a clear refusal before mutation.

**FS-3 · Upgrades that previously succeeded are now refused for databases with EQL-dependent views, policies or constraints** (medium impact, plausible)

- Trigger: A customer database has an RLS policy, view, check constraint, generated column or trigger predicate that calls eql_v3 functions, and an automated pipeline or operator runs `stash eql upgrade` / `install --force`.
- Mechanism: inspectReinstallDependencies() collects every non-index external dependant and throws EqlReinstallRefusalError (derived-search-index-restoration.ts:494-558). install.ts and upgrade.ts turn this into exit 1. At base the bundle ran and CASCADE destroyed those objects silently.
- Consequence: Upgrade pipelines that exited 0 now exit 1. Users must drop and recreate the dependent objects themselves, and the CLI offers no automated path for that. This is safer than base, which silently removed RLS policies, but it is a visible behaviour change for anyone automating upgrades. The changeset ships it as a `minor` bump.
- Affects: stash eql install --force / stash eql upgrade commands, Customer PostgreSQL databases (application tables with EQL-backed functional indexes), Published `stash` npm package programmatic API (EQLInstaller, loadBundledEqlSql)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:494-558`; `packages/cli/src/commands/db/install.ts:205-217`; `packages/cli/src/installer/__tests__/reinstall.live.test.ts:507-605`; `.changeset/safe-eql-reinstall.md:1-20`
- Existing verification: Live refusal tests for RLS policy, view, check constraint, generated column, trigger predicate, customer operators and partitioned indexes, asserting EQL is unchanged and the object remains [exists_not_run]
- Missing verification: Release-note or upgrade-guide wording that tells users how to stage dependent objects around an upgrade
- Mitigation: Document the refusal and a remediation recipe (drop, upgrade, recreate in one migration) in the changeset or upgrade notes. Consider whether a `minor` bump correctly signals a command that now exits non-zero where it used to succeed.

**FS-4 · EQL-backed index created concurrently by another session is dropped and not restored** (medium impact, speculative)

- Trigger: During an upgrade, an unrelated session (an application migration, or an operator) creates an index on an eql_v3 function between the dependency capture and the bundle's DROP SCHEMA ... CASCADE.
- Mechanism: Capture runs as its own statement (derived-search-index-restoration.ts:683). Under READ COMMITTED, the bundle's DROP ... CASCADE (next statement) sees and drops any index committed in between, and the rebuild list does not include it. The advisory lock serializes only stash commands (E-8). Verification checks only the captured identities.
- Consequence: The upgrade reports success, but one search index is missing. Queries silently fall back to sequential scans, which is the silent degradation ADR 0001 says must never happen.
- Affects: packages/cli installer (derived-search-index-restoration.ts, installer/index.ts), Customer PostgreSQL databases (application tables with EQL-backed functional indexes)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:659-695`; `packages/cli/src/installer/derived-search-index-restoration.ts:467-492`; `packages/cli/README.md:213-222`
- Missing verification: No check after the bundle runs that the set of EQL-dependent indexes destroyed equals the set captured
- Mitigation: Documented as a maintenance-window requirement. Optionally, capture with an event trigger or compare against a pre-drop re-inventory inside the transaction.

### Recommended controls

- Add a live test that runs install() as a non-superuser that owns the EQL schemas but not an indexed table, and either assert a pre-mutation refusal or make preflight report the gap. (test; FS-2, VG-2)
- In the CLI output before mutation, and in the README/skill/changeset, say that tables carrying EQL indexes are locked against reads and writes until the rebuild commits, and list the affected tables. (documentation; FS-1)
- Publish a remediation recipe for refused upgrades (views, policies, constraints) and reconsider the bump level for a command that now exits non-zero where it used to succeed. (documentation; FS-3)
- Review the exclusion filters in LIFECYCLE_DEPENDENCIES_SQL (lines 161-292), especially the public-operator and cast exemptions. A customer operator in `public` backed by an eql_v3 function is treated as bundle content and would still be dropped silently. (review_focus; FS-4)
- Confirm that the run-tests job is green on both the PG16 and PG17 legs with STASH_TEST_DATABASE_URL set, including the credentialed upgrade-encrypted-indexes suite, before release. (other; VG-1)

### What this assessment could not see

- I read the restoration module, installer/index.ts, installation-state.ts, the verify.ts diff, the command diffs and the reinstall live test closely. I only skimmed the unit-test changes (installer.test.ts, installation-state.test.ts, verify.test.ts), the SQLx uninstall test, and the registry-pin linter change. A defect in the refactored status/verify/validate paths, or in the lint exemption, could be missed.
- Not every exclusion predicate in LIFECYCLE_DEPENDENCIES_SQL was checked against PostgreSQL catalog behaviour, for example exclusion constraints or indexes in non-default tablespaces (pg_get_indexdef omits TABLESPACE, so such an index would be rebuilt in the default tablespace and still pass verification). Edge-case index shapes may be rebuilt differently from the original or refused unexpectedly.
- Pre-existing behaviour that this change does not alter: `stash eql migration` still emits the raw bundle, which cascade-drops dependent indexes when applied over an existing install. The change documents this but does not fix it. Migration-first users (the preferred path in the skill) are not protected by the new protocol.
- No deployment context: unknown whether customers run upgrade from automated pipelines against production. The likelihood of FS-1 and FS-3 cannot be judged; only their impact is assessed.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
