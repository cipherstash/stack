## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `c4ab67ac32..d4a95551a1`

Release-pipeline-only change to .github/workflows/release.yml plus two new node scripts. (1) The `release` job now waits, before `changeset publish`, until npm lists every native package that publish-ffi/publish-auth just published; this fails closed on timeout. (2) The production EQL asset jobs (eql-sql, eql-docs, eql-image) are now driven by a new `eql-assets` job that runs on every production push whatever `release` did, and decides from npm, the `eql-<version>` tag and this run's publishedPackages, building at the commit the `@cipherstash/eql@<version>` tag names. (3) The EQL jobs use `!cancelled()` plus explicit result checks instead of the implicit success(). No library code, payload or SQL changes. Because EQL is armed at head (FROZEN_PUBLISHERS is empty), merging is itself expected to create the eql-3.0.6 tag and GitHub release and dispatch an image build that moves `postgres-eql:latest` — an outward, hard-to-reverse action. The main residual risks are that the decision keys only on the eql tag, so a partly built asset set (SQL done, docs/image failed, e.g. the GHCR write access AGENTS.md still lists as open) is treated as complete on later pushes, and that the failed-publish recovery path relies on unverified changesets/action behaviour (outputs and tags on failure). Both fail loudly or leave a gap rather than shipping wrong bytes. Script tests and actionlint passed in CI, but they model GitHub semantics rather than observe them.

### Failure scenarios

**FS-1 · A partly built EQL asset set is treated as complete by every later run** (medium impact, plausible)

- Trigger: eql-sql succeeds (creating tag eql-<v> and the GitHub release) but eql-docs or eql-image fails — e.g. the image push fails because write access to ghcr.io/cipherstash/postgres-eql from this repo is still missing (AGENTS.md lists it as an open cutover step). Likely on the very first run after merge for 3.0.6.
- Mechanism: eqlAssets() returns needed=false as soon as tagCommit('eql-<v>') finds the tag (eql-release-assets.mjs:86-89); it never checks for the docs bundle or the image. eql-image additionally requires eql-docs success.
- Consequence: SQL release eql-3.0.6 exists while docs bundle and/or postgres-eql:3.0.6/:latest do not; later pushes report 'nothing owed' and never repair it. postgres-eql:latest keeps serving 3.0.5 SQL while npm and the GitHub release say 3.0.6 — a version skew between the client package and the SQL bundle customers get from the image. Recoverable by re-running failed jobs in that run or a manual dispatch.
- Affects: scripts/eql-release-assets.mjs, release-postgres-eql-image.yml and ghcr.io/cipherstash/postgres-eql floating tags, GitHub release eql-<version> (SQL install bundle, docs bundle)
- Evidence: `scripts/eql-release-assets.mjs:84-113`; `.github/workflows/release.yml:669-771`; `AGENTS.md:416-420`
- Existing verification: Job-graph test 'stops at the first EQL job that fails' and 'owes nothing once the eql-<version> tag exists' (scripts/__tests__/eql-release-assets.test.mjs), run by the Lint (Biome) job via test:scripts [ran_passed]
- Missing verification: No test or check that a run with the eql tag but missing docs assets or image is detected; No pre-merge confirmation that GHCR write access exists for this repository
- Mitigation: Confirm GHCR package write access before merging (or accept a manual image dispatch); after the first run, check the eql-3.0.6 release has both SQL and docs assets and the image tags moved; consider keying 'owed' on release assets/image tags, or emitting a warning in eql-summary when downstream EQL jobs failed.

**FS-2 · Failed-publish recovery depends on unverified changesets/action behaviour and may fail every push to main** (medium impact, plausible)

- Trigger: `changeset publish` publishes @cipherstash/eql then fails on another package (the E402 case), and changesets/action does not set publishedPackages and/or does not push the @cipherstash/eql@<v> tag when the publish command exits non-zero.
- Mechanism: eql-assets reads PUBLISHED_PACKAGES straight from steps.changesets.outputs.publishedPackages (release.yml:509) on the assumption that the action sets it on failure; if empty and npm already lists the version with no changesets tag, eqlAssets() throws (eql-release-assets.mjs:98-106). eql-assets runs on every production push (release.yml:669-676).
- Consequence: eql-assets fails on every subsequent push to main (red release workflow) until someone pushes the tag or builds the assets by hand; assets missing in the meantime. Fails closed — no wrong bytes are built.
- Affects: .github/workflows/release.yml (Release JS), scripts/eql-release-assets.mjs
- Evidence: `.github/workflows/release.yml:508-509`; `scripts/eql-release-assets.mjs:84-113`; `scripts/__tests__/eql-release-assets.test.mjs:444-459`
- Existing verification: Tests 'runs them when `changeset publish` fails' and 'refuses a version on npm when nothing says which commit published it' — inject publishedPackages into a modelled job graph; they do not exercise the real action [ran_passed]
- Missing verification: Evidence (action source or a run log) that changesets/action v1.9.0 sets publishedPackages and pushes tags when the publish command exits non-zero
- Mitigation: Reviewer to confirm changesets/action v1.9.0 failure-path behaviour; document the manual recovery (push @cipherstash/eql@<v> tag at the publishing commit) in AGENTS.md/runbook.

**FS-3 · Wait passes but changeset publish still sees a stale npm packument and fails with E402** (medium impact, speculative)

- Trigger: npm registry/CDN eventual consistency: `npm view <name> versions` returns the new version, then changesets' own `npm info` lookup hits a stale cached packument.
- Mechanism: The wait (wait-for-npm-versions.mjs:63-90) checks once per package and stops polling as soon as it is listed; changesets performs a separate lookup afterwards with no guarantee of the same view.
- Consequence: Same failure as before the change: release job fails with E402, other JS packages may already be published; re-run needed. Loud, recoverable.
- Affects: .github/workflows/release.yml (Release JS), scripts/wait-for-npm-versions.mjs, npm packages published by changeset publish (all JS workspace packages)
- Evidence: `scripts/wait-for-npm-versions.mjs:48-91`
- Existing verification: Unit/process tests of the wait with a stubbed npm [ran_passed]
- Missing verification: No production run with a native publish has exercised the wait yet
- Mitigation: Watch the next FFI/auth release; if it recurs, require the version to be listed on N consecutive polls.

### Recommended controls

- Treat merging as an EQL 3.0.6 release action: before merge confirm the @cipherstash/eql@3.0.6 tag points at 23e9af3f, that this repo can push to ghcr.io/cipherstash/postgres-eql, and that moving :latest to 3.0.6 is intended. (review_focus; FS-1)
- Watch the first post-merge Release JS run: eql-assets reports needed=true ref=23e9af3f; eql-3.0.6 release has SQL and docs bundles; image workflow pushes <pg>-3.0.6 and moves :latest. If any downstream EQL job fails, re-run failed jobs in that same run (later pushes will not repair it). (monitoring; FS-1, VG-2)
- Confirm from changesets/action v1.9.0 source that publishedPackages is set and tags are pushed (commitMode github-api) when `changeset publish` exits non-zero. (review_focus; FS-2, VG-3)
- Document recovery: for a stuck eql-assets failure push the @cipherstash/eql@<v> tag at the publishing commit; for a partial asset set dispatch _build-eql-docs / release-postgres-eql-image manually. A wrongly created eql-<v> release/tag can be deleted, but moved image floating tags must be re-pointed. (rollback_plan; FS-1, FS-2)
- On the next release that includes protect-ffi or auth, check the wait step log and that changeset publish no longer hits E402. (monitoring; FS-3)

### What this assessment could not see

- No access to npm, GitHub tags/releases, GHCR permissions or the changesets/action source; the PR's claims about the @cipherstash/eql@3.0.6 tag, the npm state and action failure behaviour are unverified. The first post-merge run's outcome (FS-1, FS-2) cannot be predicted from the inputs.
- Tests were not run locally (no node_modules/vitest); test results come only from the CI check-run conclusions, without logs. ran_passed is based on the 'Lint (Biome)' job conclusion, which runs pnpm run test:scripts unconditionally; individual test outcomes not seen.
- Test files (eql-release-assets.test.mjs, wait-for-npm-versions.test.mjs, expressions.mjs) were skimmed by test name and a few cases, not read in full; the refactor of workflow-dispatch-job-conditions.test.mjs was not reviewed for weakened assertions. A weakened pre-existing assertion would not be detected.
- The eql-assets decision only considers the current tree version; older versions on npm missing assets are not repaired. This is a scope limit of the design, not a regression. Not raised as a scenario.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
