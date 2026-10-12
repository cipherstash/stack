## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `9d221fb838..c20df92a20`

Adds a 3.0.6 EQL v3 upgrade self-edge to @cipherstash/stack-prisma and re-emits the genesis baseline (20260601T0100_install_eql_v3_bundle) to bake eql-3.0.6 with a fifth no-SQL carrier op, so the shipped baseline migrationHash moves again (bad30c9b… → 2fdc7caf…). I verified that the baked 3.0.6 SQL differs from the 3.0.5 bundle only in the version stamp (version(), schema comment, one comment line), and that the baseline and the 3.0.6 edge bake identical bytes. Because the migrations land before @cipherstash/eql is bumped from 3.0.5 (bumped by a pending patch changeset), the main risk is release ordering: the lockstep test now accepts either EQL version, so stack-prisma could ship baking 3.0.6 next to a 3.0.5 runtime package. Existing 1.x databases now re-install the bundle twice in one migrate, each install starting with DROP SCHEMA eql_v3 CASCADE. The stale-vendored-directory hazard (db init refusal, silent no-op without migration plan) was already present at the base from the unpublished 3.0.5 re-emit, and this change carries it forward. Offline tests targeting each of these paths exist but I did not see them run. The new live-Postgres tests self-skip without DATABASE_URL, and I found no CI job that sets it for this suite.

### Failure scenarios

**FS-1 · stack-prisma ships baking eql-3.0.6 while its pinned @cipherstash/eql runtime stays 3.0.5** (medium impact, plausible)

- Trigger: A Version Packages release publishes @cipherstash/stack-prisma (minor, from .changeset/eql-3-0-6-migration.md) without @cipherstash/eql moving to a 3.0.6 whose install SQL digest is exactly 9b6dab78…, e.g. the eql changeset is deferred, the eql publish fails, or another EQL SQL change lands before the bump.
- Mechanism: The lockstep test only requires that the installed release's digest is baked by some migration (migration-v3.test.ts:312), which 3.0.5 still satisfies through the 3.0.5 edge, and the version marker now accepts '3.0.5' or '3.0.6' (line 330). So CI stays green with stack-prisma baking 3.0.6 against a 3.0.5 @cipherstash/eql. The `*` in workspace:* is rewritten to the exact eql version at pack time, and eql is not in stack-prisma's fixed changeset group (.changeset/config.json).
- Consequence: Databases migrated by prisma-next report eql-3.0.6, while `stash eql install` and other tools pinned through @cipherstash/eql install or expect 3.0.5. Version-based diagnostics disagree, and the shipped migrations reference an EQL release that may not exist on npm. Function behaviour is identical (verified stamp-only diff), so there is no data or ciphertext effect.
- Affects: @cipherstash/stack-prisma migrations and control descriptor, @cipherstash/eql (workspace dependency, 3.0.5 at head), Changesets / Version Packages release flow, Customer PostgreSQL databases with EQL v3 installed via prisma-next
- Evidence: `packages/stack-prisma/test/v3/migration-v3.test.ts:306-331`; `packages/stack-prisma/DEVELOPING.md:368-387`; `.changeset/eql-repoint-manifests-to-stack.md:1-3`; `.changeset/config.json:5-14`; `python3 -I: sha256 + difflib of execute[0].sql in 20260814T0000_upgrade_eql_v3_3_0_5/ops.json vs 20261002T0000_upgrade_eql_v3_3_0_6/ops.json and baseline ops.json`
- Existing verification: Lockstep test: installed eql digest must be baked by a published migration (fails loudly if eql moves to a digest no migration bakes) [exists_not_run]; Offline test asserting both 3.0.6-baking edges contain SELECT '3.0.6' and every version postcheck reads '3.0.6' [exists_not_run]
- Missing verification: No check that a stack-prisma release whose baseline bakes eql-X is published together with @cipherstash/eql X (the baseline's digest is not required to equal the installed release's); No CI result showing the Version Packages PR (bumping eql to 3.0.6) passes the lockstep test with digest 9b6dab78…
- Mitigation: Release the stack-prisma changeset only in the same Version Packages PR that bumps @cipherstash/eql to 3.0.6. Before publishing, confirm that the built eql package's installSqlSha256 equals 9b6dab78…. Narrow the version marker to '3.0.6' right after that merge, and consider adding a release gate that the baseline's baked digest equals the installed releaseManifest.

**FS-2 · A version-stamp-only release re-runs DROP SCHEMA eql_v3 CASCADE on existing databases** (medium impact, plausible)

- Trigger: `prisma-next plan` + `migrate` against an existing database whose markers lack the 3.0.6 invariant: every 1.0.0/1.1.x database (walks 3.0.5 then 3.0.6), and any database already at 3.0.5 built from main.
- Mechanism: The 3.0.6 edge executes the full install bundle (migration.ts:75), which drops and recreates the eql_v3 schema with CASCADE. For 1.x databases this runs a second full ~2.6 MB install in the same transaction as the 3.0.5 edge. For a database already at 3.0.5 it is a new destructive reinstall for a stamp-only change. Dependent functional indexes, views, RLS policies and grants on eql_v3 objects are dropped and not recreated by the migration.
- Consequence: After the upgrade, encrypted-column queries lose their functional indexes (slow queries) and RLS policies or grants that referenced eql_v3 are gone until the operator recreates them. A longer single transaction holds locks for longer. No ciphertext is altered, because the public.eql_v3_* storage domains are preserved.
- Affects: Customer PostgreSQL databases with EQL v3 installed via prisma-next, @cipherstash/stack-prisma migrations and control descriptor
- Evidence: `.changeset/eql-3-0-6-migration.md:22-33`; `packages/stack-prisma/test/v3/stale-vendored-space.test.ts:578-607`; `packages/stack-prisma/README.md:32-67`
- Existing verification: Offline path tests: 1.x database walks [3.0.5, 3.0.6]; a 3.0.5 database walks only 3.0.6; stale fresh space installs the bundle three times [exists_not_run]; Live-PG test applying the 3.0.5 then 3.0.6 edges' baked SQL in one transaction and checking postchecks (self-skips without DATABASE_URL and CS credentials) [exists_not_run]
- Missing verification: No test that dependent objects (functional indexes, RLS policies) are reported or restored after the second reinstall; No evidence the live-PG suite runs in any CI job
- Mitigation: Already documented in the changeset (re-run grants, recreate indexes). Make the release notes call out that this happens even for a stamp-only bump, and consider a precheck that skips the reinstall when eql_v3.version() is already ≥ 3.0.6, or emits a list of the dependent objects it will drop.

**FS-3 · Temporarily widened lockstep marker and known-red live check outlive the release cycle** (low impact, speculative)

- Trigger: The follow-up to narrow the marker to '3.0.6' after the eql bump is forgotten, or the red live byte-identity check is ignored as expected noise.
- Mechanism: migration-v3.test.ts:330 accepts two versions, and migration-apply-live-pg.test.ts:168-171 is documented as failing by construction until the bump merges. Both rely on a manual follow-up.
- Consequence: Weaker guard against a future eql/stack-prisma pairing drift, or a live check that people learn to ignore. Detection is degraded, but nothing is directly broken.
- Affects: @cipherstash/stack-prisma migrations and control descriptor, @cipherstash/eql (workspace dependency, 3.0.5 at head)
- Evidence: `packages/stack-prisma/test/v3/migration-v3.test.ts:306-331`; `packages/stack-prisma/DEVELOPING.md:368-387`; `packages/stack-prisma/test/live/migration-apply-live-pg.test.ts:166-171`
- Missing verification: No automated reminder or test that fails once @cipherstash/eql is 3.0.6 and the marker still lists 3.0.5
- Mitigation: Track the narrowing as a required follow-up in the Version Packages PR checklist.

### Recommended controls

- Publish stack-prisma 1.2.0 only in the same release as @cipherstash/eql 3.0.6. Before publishing, confirm that the packed eql tarball's installSqlSha256 is 9b6dab789248f911707f7c1c468c5d455987b47aac4a30fc421bc813073fffb1. (rollback_plan; FS-1, VG-3)
- Run the stack-prisma unit suite and test/live against a real Postgres (DATABASE_URL + CS creds) on the Version Packages branch before publishing. (test; FS-2, VG-1, VG-2)
- Reviewer: check migration-v3.test.ts:306-331 (lockstep and widened marker) and the 3.0.6 migration.ts op. Confirm the plan to narrow the marker after the bump. (review_focus; FS-1, FS-3)
- In the 1.2.0 release notes, state clearly that existing databases have eql_v3 dropped and reinstalled (twice for 1.x), and list what operators must recreate. (documentation; FS-2)

### What this assessment could not see

- The ~2.6 MB baked SQL in each ops.json was compared programmatically (sha256 and line diff of the 3.0.5 vs 3.0.6 edges) rather than read. The stamp-only claim rests on that diff; the 3.0.5 bundle itself was not re-reviewed (pre-existing).
- The stale-vendored-directory hazards (fresh `db init` refusal; `migrate` without `plan` silently stays on 3.0.4) already exist at the base, from the unpublished 3.0.5 re-emit. They were not counted as scenarios of this change. This change also makes directories vendored from main at bad30c9b… stale. The npm-visible baseline break is real for 1.x consumers but is attributed to the base.
- Adoption figures and npm publish history in the changesets (144 downloads, 1.1.x shipped 3.0.4) could not be checked offline. Blast-radius reasoning for the baseline re-emit is unverified.
- The prisma-next migrator's planning and runner skip rules were not read; behaviour relies on the repository's own offline tests that pin the paths. Path claims (which edges are walked) are taken from tests, not the planner source.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
