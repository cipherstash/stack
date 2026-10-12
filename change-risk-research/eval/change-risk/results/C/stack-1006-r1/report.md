## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `9d221fb838..c20df92a20`

Adds a new EQL 3.0.6 upgrade self-edge (20261002T0000_upgrade_eql_v3_3_0_6) to @cipherstash/stack-prisma and re-emits the v3 baseline migration so it bakes the 3.0.6 install SQL (sha256 9b6dab78…) and carries a fifth no-SQL invariant carrier op; the head ref now requires the 3.0.6 invariant. The PR deliberately lands before the Version Packages PR (#938) that bumps @cipherstash/eql 3.0.5 → 3.0.6, so at head the in-tree @cipherstash/eql is still 3.0.5 (manifest accde003…) while the baseline bakes 3.0.6 bytes that nothing in-tree attests; the eqlVersion marker test was loosened to accept both. The released artefacts change a published baseline identity (1.1.x 10306543… → 2fdc7caf…) and add one more DROP SCHEMA eql_v3 CASCADE reinstall to every existing database's upgrade path. The functional SQL difference is the version stamp only (verified in the baked bytes). Offline stack-prisma tests ran and passed in CI; the live apply suite that executes the baked SQL did not run in CI. The material risks are release-ordering with #938, stale vendored migration spaces in consumer repos, and the reinstall cascade on existing databases — all documented by the change, none high-impact on their own.

### Failure scenarios

**FS-1 · Baked 3.0.6 bytes and the eventual @cipherstash/eql 3.0.6 release drift apart, or release order is inverted** (medium impact, plausible)

- Trigger: #938 is regenerated with further EQL SQL changes before merging (so its 3.0.6 install digest is no longer 9b6dab78…), or a stack-prisma release is cut from main before #938 merges.
- Mechanism: At head the in-tree manifest is eql 3.0.5 / accde003… (E-9), yet the baseline and new edge bake 9b6dab78… (E-6). Those bytes are pinned only against themselves in PUBLISHED_MIGRATIONS; the lockstep test passes at head only because the 3.0.5 edge still bakes accde003… (E-10), and the eqlVersion marker accepts both versions (E-11). Provenance of 9b6dab78… rests on the PR's account of emitting against #938's files (E-19).
- Consequence: Case 1: the lockstep test fails on #938 (loud) and a further migration plus another baseline re-pin is needed. Case 2: a stack-prisma release would pin @cipherstash/eql 3.0.5 exactly while db init installs a bundle stamped 3.0.6, so the CLI/stack installer and the Prisma migrations disagree on the installed version for those users, and the frozen artefact cannot be corrected without another re-emit.
- Affects: @cipherstash/stack-prisma migrations (baseline + 3.0.6 edge), @cipherstash/eql 3.0.6 release via Version Packages PR #938, Customer PostgreSQL databases using stack-prisma
- Evidence: `git show c20df92a:<baseline and 3.0.6 ops.json> | grep -o "SELECT '3.0.[0-9]'|COMMENT ON SCHEMA eql_v3 IS ..."`; `packages/eql/packages/eql/src/generated/release-manifest.ts:1-6`; `packages/stack-prisma/test/v3/migration-v3.test.ts:306-314`; `packages/stack-prisma/test/v3/migration-v3.test.ts:323-330`; pr_description (inferred)
- Existing verification: Lockstep test ('installed @cipherstash/eql release is baked by some published migration') will compare #938's manifest digest against 9b6dab78… when #938's CI runs [exists_not_run]; Run Tests (Node 22/24/Bun) passed on head, with in-tree eql 3.0.5 [ran_passed]
- Missing verification: No in-tree attestation that 9b6dab78… is the genuine EQL 3.0.6 build until #938 lands; No gate preventing a stack-prisma publish while the eqlVersion marker accepts two versions
- Mitigation: Merge #938 immediately after this PR, confirm #938's release-manifest installSqlSha256 is 9b6dab78… and its lockstep test is green before publishing, then narrow the eqlVersion marker to '3.0.6'.

**FS-2 · Consumers with a stale vendored migrations/cipherstash/ fail db init or silently stay on the old bundle** (medium impact, plausible)

- Trigger: A consumer upgrades to the release carrying this change without deleting migrations/cipherstash/, or runs migrate/db init without migration plan first. Also applies to spaces vendored from main at the unpublished 3.0.5 baseline (bad30c9b…).
- Mechanism: The baseline's identity changes again (E-4, E-5). The seed phase keeps an existing baseline directory but overwrites refs/head.json, which now also requires the 3.0.6 invariant (E-8). A stale genesis edge does not carry it, so db init (additive-only) must plan the data-class 3.0.6 self-edge and is refused; without a seed run the new edges are never on disk (E-18).
- Consequence: Fresh-database db init fails with a POLICY_VIOLATION naming only an op id; migrate without plan leaves the database on the older bundle without warning. The bundle difference is only the version stamp, so no functional or data effect beyond the failed or skipped run.
- Affects: Consumer repos with vendored migrations/cipherstash/, Customer PostgreSQL databases using stack-prisma, @cipherstash/stack-prisma migrations (baseline + 3.0.6 edge)
- Evidence: `packages/stack-prisma/migrations/20260601T0100_install_eql_v3_bundle/migration.ts:232-248`; `packages/stack-prisma/migrations/refs/head.json`; `.changeset/eql-3-0-6-migration.md:22-44`; `packages/stack-prisma/test/v3/stale-vendored-space.test.ts:609-635`
- Existing verification: stale-vendored-space.test.ts pins the db init refusal (DEFECT test), the 1.1.x and 3.0.5 walks, and the no-seed silent skip; ran as part of the passing CI test jobs [ran_passed]
- Missing verification: The refusal message still does not name the stale directory or the remedy (pinned as a known defect, not fixed)
- Mitigation: Keep the 'Action required' notice prominent in the 1.2.0 release notes; consider making the db init refusal point at the vendored directory. Pre-existing from the unpublished 3.0.5 re-emit, so the npm-visible change happens once.

**FS-3 · The 3.0.6 reinstall drops objects that depend on eql_v3 on every existing database, for a version-stamp-only release** (medium impact, plausible)

- Trigger: prisma-next migrate against an existing database (1.x from npm, or one already at 3.0.5 built from main) that has functional indexes, RLS policies, views or constraints referencing eql_v3 / eql_v3_internal objects.
- Mechanism: The new edge executes the full install SQL (E-1), which begins with DROP SCHEMA IF EXISTS eql_v3 CASCADE and eql_v3_internal CASCADE (E-3). 1.0.0/1.1.x databases walk the 3.0.5 and 3.0.6 edges in one run (E-2), reinstalling twice.
- Consequence: Dependent customer objects are dropped without error: ORE/HMAC indexes disappear (queries degrade to scans, unique constraints backed by them stop being enforced) and RLS policies calling eql_v3 functions are removed until the customer recreates them. Upgrade runs take longer, and DDL locks are held longer. For npm users this cascade already happened once with the 3.0.5 edge at base; the new exposure is databases already at 3.0.5 and the second reinstall.
- Affects: Customer PostgreSQL databases using stack-prisma
- Evidence: `packages/stack-prisma/migrations/20261002T0000_upgrade_eql_v3_3_0_6/migration.ts:66-75`; `packages/stack-prisma/migrations/20261002T0000_upgrade_eql_v3_3_0_6/migration.ts:19-25`; `python3: sha256 and regex over execute[0].sql of packages/stack-prisma/migrations/20261002T0000_upgrade_eql_v3_3_0_6/ops.json at head`; `.changeset/eql-3-0-6-migration.md:22-44`; `skills/stash-prisma/SKILL.md:225-312`
- Existing verification: Live suite applies the 3.0.4→3.0.5→3.0.6 walk and db-init baseline on an empty eql_v3 (no dependent customer objects); gated on DATABASE_URL and CipherStash credentials, not run in CI; PR reports a local 7/7 pass [exists_not_run]
- Missing verification: No test applies the upgrade edges to a database with dependent indexes/RLS policies and checks what survives; No timing or lock measurement of the double reinstall on a populated database
- Mitigation: Release notes already say to recreate indexes and grants after migrate (E-13); state explicitly that 3.0.6 changes only the version stamp, so recreating is the only action. Consider running the live migration suite in CI with a seeded table and index.

### Recommended controls

- Before publishing, confirm #938's release-manifest installSqlSha256 is 9b6dab78… and its lockstep test is green; publish stack-prisma and @cipherstash/eql together from #938. (compatibility_check; FS-1, VG-2)
- Narrow the eqlVersion marker to '3.0.6' and make the live byte-identity check green right after #938 merges (follow-up named in the PR). (other; FS-1)
- Run migration-apply-live-pg against Postgres in CI (or once manually on the #938 branch), ideally with a table carrying an ORE/HMAC index, to confirm the end state and record what the cascade drops. (test; FS-3, VG-1, VG-3)
- In the 1.2.0 release notes, lead with the vendored-directory delete + migration plan step and the post-migrate index/grant/RLS recreation; update skills/stash-supabase once 3.0.6 ships. (documentation; FS-2, FS-3)
- Review the baseline re-emit decision itself (third re-pin of a frozen digest) against the append-only rule, and confirm createdAt is unchanged. (review_focus; FS-2)

### What this assessment could not see

- PR #938, the release workflow and npm tarball contents were not available; the claims about which baseline each npm version shipped and the download counts come only from the PR description and code comments. The statement that npm users see one baseline change, and the ordering assumptions in FS-1, are unverified.
- The 2.6 MB baked SQL was not read in full; I verified its sha256 (9b6dab78…), the 3.0.6 version stamps, and the DROP SCHEMA CASCADE statements. I did not diff it against the 3.0.5 SQL myself. The 'version stamp only' claim rests on the PR text plus the stamps I checked.
- Prisma Next migrator internals (planner, ledger checks against migrationHash) were not read; behaviour for databases whose ledger recorded the bad30c9b… baseline is taken from the tests and comments. Edge cases for main-built databases after a delete-and-replan are not assessed independently.
- The reinstall cascade on dependent objects is a property of the EQL bundle design and was already present for the 3.0.2/3.0.4/3.0.5 edges at base. FS-3 rates only the exposure this change adds, not the overall design.
- I did not run any tests locally; test status comes only from ci.json. Eleven check runs were skipped and the combined status is 'pending'. Verification confidence is limited to what CI ran.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
