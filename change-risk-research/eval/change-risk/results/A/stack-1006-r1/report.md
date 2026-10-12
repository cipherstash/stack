## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `9d221fb838..c20df92a20`

Adds an EQL 3.0.6 upgrade self-edge (20261002T0000_upgrade_eql_v3_3_0_6) to @cipherstash/stack-prisma and re-emits the genesis baseline to bake eql-3.0.6 with a fifth no-SQL carrier op. The baked 3.0.6 bundle differs from 3.0.5 only in the version stamp (verified by diffing the SQL embedded in the two ops.json files), and offline and live tests pin the path order, hashes and postchecks. The release risk is not in the SQL content. It comes from what applying the edge does to customer databases. Every existing database must walk a data-class edge that runs the full bundle, starting with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, through the raw Prisma migration path. That path has none of the CLI's dependency capture or refusal. Databases on the published 1.x releases (eql-3.0.4) do this twice in one plan. Dependent RLS policies, functional indexes, constraints and grants are dropped silently, for a release with no behavioural change. Tests cover only a clean schema with no dependents, and no test result was available. A secondary concern is the deliberate interim state on main: the lockstep marker is relaxed to accept 3.0.5 or 3.0.6, and the live byte-identity test is known to fail until the @cipherstash/eql bump merges. The baseline re-emit that orphans vendored 1.x `migrations/cipherstash/` directories was already present at base. It is noted as a limitation.

### Failure scenarios

**FS-1 · Stamp-only 3.0.6 edge silently drops RLS policies, functional indexes and grants on every existing database** (high impact, plausible)

- Trigger: A customer with an existing EQL v3 database (installed via stack-prisma 1.x or main) upgrades the package and runs `prisma-next migration plan` + `migrate`, and has objects outside eql_v3 that reference eql_v3 functions/operators (RLS policies, functional or expression indexes, CHECK constraints, views) or role grants on the schema.
- Mechanism: The 3.0.6 op is a data-class self-edge whose execute step is the full bundle from readVerifiedInstallSql() (migration.ts:66-75). The baked SQL begins `DROP SCHEMA IF EXISTS eql_v3 CASCADE; DROP SCHEMA IF EXISTS eql_v3_internal CASCADE;`, verified in the embedded ops.json. The Prisma migration path runs that raw SQL. The CLI's capture-and-restore of functional indexes and its refusal of policies and views do not apply here (safe-eql-reinstall changeset: 'Generated EQL migrations contain the raw bundle and do not include these reinstall protections'). The op's postchecks only verify the version stamp and one domain, so the run succeeds. A 1.x database walks the 3.0.5 and then the 3.0.6 edge, so this happens twice.
- Consequence: PostgreSQL only emits NOTICEs for the cascaded drops. RLS policies that referenced eql_v3 vanish: on a table with other permissive policies this widens row access, and on a table with none it denies all rows. Functional indexes on encrypted columns disappear, so encrypted equality and range queries fall back to sequential scans or time out. Grants the application role held on eql_v3 are lost, so encrypted queries fail with permission errors. All of this follows from a release whose SQL changes only a version string.
- Affects: @cipherstash/stack-prisma migration artefacts (packages/stack-prisma/migrations), Customer PostgreSQL databases migrated with prisma-next, Objects outside eql_v3 that depend on it (RLS policies, functional indexes, constraints, grants)
- Evidence: `packages/stack-prisma/migrations/20261002T0000_upgrade_eql_v3_3_0_6/migration.ts:60-89`; `packages/stack-prisma/migrations/20261002T0000_upgrade_eql_v3_3_0_6/ops.json`; `packages/eql/src/v3/version.template:26-37`; `.changeset/safe-eql-reinstall.md:6-20`; `.changeset/eql-3-0-6-migration.md:22-33`; `packages/cli/src/messages.ts:301`
- Existing verification: Live test applies the 3.0.5 then 3.0.6 edges to an eql-3.0.4 schema and checks the end version and postchecks. It runs on a schema with no dependent objects. [exists_not_run]; The 3.0.6 changeset tells users to re-run grant scripts and recreate functional indexes and dependants after the CASCADE. [exists_not_run]
- Missing verification: A live test that applies the 3.0.6 edge to a database with a dependent RLS policy, functional index and role grant, and asserts what survives.; A precheck on the upgrade op that detects objects depending on eql_v3/eql_v3_internal and refuses (or at least names them) before the CASCADE.
- Mitigation: Before release, put the CASCADE warning in the README's 'Upgrading from 1.0.0 or 1.1.x' section and the shipped skill, not only the changeset. Consider a precheck on the 3.0.6 (and 3.0.5) upgrade op that queries pg_depend for external dependants and fails with an actionable message. Tell users to run the upgrade in a maintenance window with a schema dump of policies, indexes and grants to restore from.

**FS-2 · 1.x upgrade holds locks for two full bundle reinstalls in one transaction** (medium impact, plausible)

- Trigger: A production database on the published eql-3.0.4 baseline runs `migrate` with this release while the application is serving traffic.
- Mechanism: The planner walks the 3.0.5 and 3.0.6 self-edges back to back, each executing the ~2.6 MB bundle including DROP SCHEMA ... CASCADE. The live test models the runner as applying the whole plan in one transaction (live test line 233; runner behaviour not read directly). Dropping cascaded indexes or policies on application tables takes ACCESS EXCLUSIVE locks on those tables, which are held until commit.
- Consequence: The window in which application queries on encrypted tables block, and in which eql_v3 functions are absent mid-transaction for other sessions waiting on locks, roughly doubles compared with a single upgrade edge. A longer migration is also more likely to hit statement or lock timeouts and roll back.
- Affects: Customer PostgreSQL databases migrated with prisma-next, Objects outside eql_v3 that depend on it (RLS policies, functional indexes, constraints, grants)
- Evidence: `packages/stack-prisma/test/live/migration-apply-live-pg.test.ts:223-254`; `packages/stack-prisma/test/v3/stale-vendored-space.test.ts:496-527`; `.changeset/eql-3-0-6-migration.md:22-33`
- Existing verification: Offline path test pins the walk 3.0.5 → 3.0.6 and their order; live test asserts the end state. Neither measures duration or locking. [exists_not_run]
- Missing verification: A measurement of upgrade duration and locks held on a representative database with encrypted tables and indexes.
- Mitigation: Document the expected duration and lock behaviour and advise a maintenance window for 1.x upgrades. Alternatively, accept the 3.0.5 edge as redundant on this path if the framework allows marking it satisfied by the later edge.

**FS-3 · Relaxed lockstep marker lets stack-prisma ship baking 3.0.6 against @cipherstash/eql 3.0.5** (low impact, plausible)

- Trigger: A release of the fixed stack group is cut before, or without, the @cipherstash/eql 3.0.5 → 3.0.6 bump. For example, the Version Packages PR is regenerated without the eql changeset, or eql publishing fails.
- Mechanism: At head, in-tree @cipherstash/eql is 3.0.5, while the baseline and 3.0.6 edge bake 9b6dab78…. The lockstep test only requires that the installed digest is baked by some migration, which the 3.0.5 edge satisfies, and the marker now accepts '3.0.5' or '3.0.6'. Nothing offline fails in that state. The only check that would fail is the live byte-identity test, which is documented as red by construction in this window.
- Consequence: A published stack-prisma whose packed @cipherstash/eql pin (and @cipherstash/stack / stash CLI manifest) says 3.0.5, while its migrations install 3.0.6. The SQL behaviour is the same apart from the stamp, but the version reported by tools disagrees with the database. A follow-up `stash eql install`/`upgrade` could reinstall 3.0.5 (another CASCADE) while the Prisma markers still record the 3.0.6 invariant.
- Affects: @cipherstash/stack-prisma migration artefacts (packages/stack-prisma/migrations), @cipherstash/eql package and the Version Packages release
- Evidence: `packages/eql/packages/eql/package.json:3`; `packages/stack-prisma/test/v3/migration-v3.test.ts:306-313`; `packages/stack-prisma/test/v3/migration-v3.test.ts:330`; `packages/stack-prisma/DEVELOPING.md:368-387`; `.changeset/eql-repoint-manifests-to-stack.md:1-3`
- Existing verification: Lockstep test (installed digest baked by some migration) plus a relaxed version marker. [exists_not_run]
- Missing verification: A release-time check that the baseline's baked digest equals the installed @cipherstash/eql manifest digest (not just 'some migration').
- Mitigation: Make sure the eql 3.0.6 bump and this stack-prisma minor release go out in the same Version Packages PR. Narrow the marker to '3.0.6' and re-green the live byte-identity test right after the bump. Consider asserting baseline digest == installed manifest digest in the release workflow.

### Recommended controls

- Add the DROP SCHEMA ... CASCADE consequence (policies, functional indexes, grants) and the maintenance-window advice to the README upgrade section and the shipped stash-prisma skill, alongside the existing double-install note. (documentation; FS-1, FS-2)
- Extend migration-apply-live-pg with a fixture that has an RLS policy, a functional index and a role grant depending on eql_v3, apply the 3.0.5 → 3.0.6 walk, and assert the documented outcome. (test; FS-1, VG-1)
- Consider a precheck on upgrade ops that lists external pg_depend dependants and refuses with an actionable message, matching the CLI's reinstall refusal. (other; FS-1)
- Gate the release on the @cipherstash/eql 3.0.6 bump in the same Version Packages PR. Afterwards, narrow the eqlVersion marker to '3.0.6' and confirm the live byte-identity test is green. (compatibility_check; FS-3, VG-2)

### What this assessment could not see

- The ~2.6 MB SQL bodies in ops.json were not read in full. Only the 3.0.5 and 3.0.6 embedded bundles were diffed (stamp-only difference), the baseline and 3.0.6-edge digests were hashed, and the DROP/CREATE DOMAIN structure was scanned. Conclusions about the SQL content rely on that diff and the digest match, not on a line-by-line review.
- prisma-next runner and planner internals (transaction scope, neighbour ordering, the seed phase) were not read. Their behaviour is taken from in-repo tests and comments. FS-2's single-transaction assumption is inferred.
- No tests were run: dependencies are not installed and there is no network. CI results were not provided. Verification confidence rests on test code read, not on results.
- Pre-existing at base, not counted as a scenario: re-emitting the published baseline means consumers with a vendored 1.x `migrations/cipherstash/` must delete and re-plan. Otherwise `db init` on a fresh database fails with an unhelpful policy error, and `migrate` without `plan` silently skips the upgrade edges. This change extends the hazard to the 3.0.6 edge and to databases vendored from main at 3.0.5. Release notes must keep the delete-and-re-plan instruction; that risk is not reassessed here.
- No deployment context or adoption data beyond what the changeset claims (144 downloads in September 2026); the number of databases with dependent policies or indexes is unknown. Impact is assessed for an affected database, not for how many exist.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
