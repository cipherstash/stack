## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `c806cfd83c..37c32967ba`

This change moves the EQL release pipeline (SQL, docs, crate, image and prerelease npm) out of the unused packages/eql/.github/ directory into root workflows, and merges it into the shared release.yml. It stays inert because its `armed` switch is derived from FROZEN_PUBLISHERS, which still lists @cipherstash/eql. The only behaviour that goes live on merge is in the shared JS/FFI release workflow: a new workflow_dispatch trigger and a `classify` job whose `mode == 'production'` guard now sits in front of ffi-artifacts, publish-ffi and release. That guard is correct at head, and CI passed (including the scripts self-tests, actionlint and the no-caching lint), but no test checks it under a dispatch from a branch other than main. Everything else stays latent until the Phase-5 cutover deletes the frozen entry. From then on the main risks are: the crate (release-plz runs on its own trigger) and npm drifting out of lockstep; an npm release whose SQL/docs/image chain has no recovery path if it fails after publishing; and GitHub-release/image SQL rebuilt separately from the bytes npm and the crate ship, with no digest cross-check. No EQL release job has ever run in this repository.

### Failure scenarios

**FS-1 · No test pins the production-mode guard on the JS/FFI publish jobs, now that release.yml can be dispatched** (high impact, plausible)

- Trigger: A later edit to release.yml drops or misspells `needs.classify.outputs.mode == 'production'` on release, publish-ffi or ffi-artifacts. Someone then dispatches release.yml from a feature branch, which is the documented way to cut an EQL prerelease.
- Mechanism: Before this change, release.yml ran only on a push to main. workflow_dispatch now reaches every job from any ref (release.yml:35-43). The only thing keeping the credentialed changesets/FFI jobs off a non-main ref is the new mode guard (release.yml:194-207, 343-362). workflow-dispatch-job-conditions.test.mjs holds classify at mode=production and models only a dispatch against main, and no test references outputs.mode.
- Consequence: Unreviewed branch code gets published to npm under the repository's trusted-publisher identity, or a Version Packages commit/PR gets driven from a feature branch. npm publishes cannot be withdrawn; the only fix is a new release.
- Affects: .github/workflows/release.yml (JS + FFI + EQL release), Published JS and FFI npm packages (@cipherstash/stack, protect-ffi and its platform packages, etc.)
- Evidence: `.github/workflows/release.yml:35-43`; `.github/workflows/release.yml:194-207`; `.github/workflows/release.yml:343-362`; `scripts/__tests__/workflow-dispatch-job-conditions.test.mjs:77-98`; `grep -rn "outputs.mode\|mode == 'production'" scripts/__tests__/`; signal `hotspots`
- Existing verification: The guard is present on all three jobs at head (read directly). No result shows how it evaluates on a branch dispatch. [exists_not_run]; The scripts self-tests (including workflow-dispatch-job-conditions) ran in CI and passed, but they model only a dispatch against main. [ran_passed]
- Missing verification: A test that evaluates every id-token/contents-write job in release.yml under classify mode=prerelease and mode=skip, and asserts that only the EQL prerelease jobs can run.
- Mitigation: Add that test. Also consider a GitHub environment with a main-only deployment branch policy on the publishing jobs, so the guard is not the only control.

**FS-2 · Once armed, the crate and npm EQL releases can diverge, because release-plz does not depend on release.yml's outcome** (medium impact, plausible)

- Trigger: After the cutover, the Version Packages merge bumps EQL and release.yml's gate refuses (because of another package's blocker), changesets publish fails, or the npm trusted publisher has not been repointed yet. Or the reverse happens: GPG_PRIVATE_KEY or the crates.io publisher is missing while npm succeeds.
- Mechanism: release-plz.yml starts on the same push (paths packages/eql/**) and is gated only on eql-armed (release-plz.yml:26-78). Its header and eql-pipeline-armed.mjs:16-19 say it deliberately does not consult the gate or npm. A different reader (release-gate) holds the production npm publish, and AGENTS.md notes that nothing asserts the two agree.
- Consequence: eql-bindings V lands on crates.io (immutable, can only be yanked) with no matching @cipherstash/eql V on npm, SQL release or image, or the other way round. Either way it breaks the one-version, five-artefact lockstep the release design depends on.
- Affects: @cipherstash/eql npm package, eql-bindings crate (crates.io) via release-plz.yml, scripts/eql-pipeline-armed.mjs + scripts/release-gate.mjs FROZEN_PUBLISHERS
- Evidence: `.github/workflows/release-plz.yml:26-78`; `scripts/eql-pipeline-armed.mjs:16-19`; `AGENTS.md:335-356`; `scripts/release-gate.mjs:377-389`; pr_description
- Existing verification: The eql-pipeline-armed tests assert which jobs carry the armed guard, in both states. [ran_passed]
- Missing verification: No check that the crate publish and the npm publish for a version either both succeeded or both did nothing.; The cutover's external configuration (crates.io and npm trusted publishers, GPG secret) cannot be verified from the repository.
- Mitigation: At the cutover, check publisher config and secrets before deleting the frozen entry. Consider having release-plz wait for, or be dispatched by, a successful release.yml EQL publish, as the prerelease path already does.

**FS-3 · GitHub-release and image SQL are rebuilt separately from the bytes npm and the crate ship, with no digest cross-check** (high impact, plausible)

- Trigger: An armed production release where the CI rebuild differs from the committed bundle, for example through toolchain drift under rust 'latest', or SQL source edited without regenerating the committed assets.
- Mechanism: npm and the crate ship the committed, version-stamped bundle. eql-sql rebuilds it with `mise run --force build --version V` (_build-eql-sql.yml:80-124), and the image workflow builds it a third time (release-postgres-eql-image.yml:97-107). Neither compares its result with the committed release-manifest digest, and the version stamp matches by construction. AGENTS.md records that regenerating from source is not proven to reproduce the published bytes, and that a same-version SQL skew has happened before.
- Consequence: Customers who install from the eql-<V> GitHub release or use the postgres-eql:<V> image get SQL functions that differ from @cipherstash/eql@V, while every version check agrees. This is the silent-mismatch class the repository's gate exists to catch.
- Affects: @cipherstash/eql npm package, eql-<V> GitHub release SQL/docs assets, ghcr.io/cipherstash/postgres-eql image
- Evidence: `.github/workflows/_build-eql-sql.yml:80-124`; `.github/workflows/release-postgres-eql-image.yml:57-107`; `AGENTS.md:425-431`; `packages/eql/packages/eql/scripts/verify-release-assets.mjs:42-59`
- Existing verification: The reusable SQL workflow forces the rebuild so the stamp is correct (asserted by the eql-sql-asset-freshness test). [ran_passed]; The npm prepublish verifier checks the stamp of the committed bundle only. [exists_not_run]
- Missing verification: A step in _build-eql-sql.yml (and in the image build) that compares the rebuilt bundle's sha256 with installSqlSha256 in packages/eql/packages/eql/sql/release-manifest.json and fails on a mismatch.
- Mitigation: Attach the committed bundle (or fail on a digest mismatch) instead of trusting a separate rebuild, and have the image use the eql-sql release asset.

**FS-4 · If an armed production release fails after the npm publish, nothing can produce the SQL, docs and image afterwards** (medium impact, plausible)

- Trigger: After the cutover, @cipherstash/eql V publishes in `release`, but eql-sql/eql-docs/eql-image fail (runner unavailable, asset upload error, GHCR permission still held by the old repository). The run is then re-run in full, or a new push follows.
- Mechanism: The production EQL chain depends only on eql_published, taken from changesets' publishedPackages in that run (release.yml:504-530, 533-605). A fresh run finds V already published and skips the chain, and the production chain has no dispatch input for targeting an existing version.
- Consequence: npm V exists with no eql-<V> SQL release, docs bundle or image, and someone has to rebuild them by hand outside the hardened pipeline.
- Affects: .github/workflows/release.yml (JS + FFI + EQL release), @cipherstash/eql npm package, eql-<V> GitHub release SQL/docs assets, ghcr.io/cipherstash/postgres-eql image
- Evidence: `.github/workflows/release.yml:504-530`; `.github/workflows/release.yml:533-605`; pr_description
- Existing verification: None. No EQL release job has run in this repository. [unknown]
- Missing verification: A documented, tested recovery path, such as a dispatch that builds and attaches the assets for a version that is already published.
- Mitigation: Add a dispatchable recovery entry for the SQL/docs/image chain that takes an explicit version, or rely on 're-run failed jobs' and document that a full re-run skips the chain.

### Recommended controls

- Extend workflow-dispatch-job-conditions.test.mjs to model classify mode=prerelease and mode=skip, and assert that release, publish-ffi and ffi-artifacts are skipped. (test; FS-1, VG-1)
- Review the classify job and the production guards in release.yml (lines 58-127, 194-207, 343-362). They are the only live change to the JS/FFI release path. (review_focus; FS-1)
- Add a sha256 check to _build-eql-sql.yml and the image build against installSqlSha256 in the committed release-manifest. (compatibility_check; FS-3, VG-3)
- Before deleting the FROZEN_PUBLISHERS entry, take a prerelease through the dispatch path end to end, and confirm the npm/crates.io publishers, the GPG secret and GHCR write access. (staged_rollout; FS-2, FS-4, VG-2)
- Document how to recover from a production run that published npm but failed in the SQL/docs/image chain, and from crate/npm divergence. (rollback_plan; FS-2, FS-4)

### What this assessment could not see

- Read closely: the release.yml diff, eql-pipeline-armed.mjs, release-plz.yml, release-postgres-eql-image.yml, _build-eql-sql.yml, the npm-publish/verify-release-assets diffs, the caching lint diff, and the relevant sections of release-gate.mjs. Skimmed or not read: _build-eql-docs.yml, most test diffs, the prose changes to AGENTS.md/SECURITY.md/docs, and the deleted upstream files. Defects in the docs workflow, or test assertions that were weakened, could be missed.
- Registry, secret, environment-protection and trusted-publisher configuration are unavailable. It is not possible to tell whether npm/crates.io would accept or reject a mis-gated publish. The consequences in FS-1 and FS-2 assume they would accept it.
- workflow_dispatch runs the workflow file from the dispatched ref, so the in-file mode guard does not stop a user with write access who edits release.yml on a branch. That exposure already existed through push triggers on a modified branch file, so it is not attributed to this change. FS-1 is assessed as a risk of accidental regression, not as a change in access control.
- release-postgres-eql-image.yml builds without `--force`. This was judged harmless because the release/ outputs are gitignored and the runner is fresh, but mise's caching behaviour was not run to confirm it. A small chance remains of a stale stamp in the image if the outputs already exist on the runner.
- No tests were run locally. CI results are taken as reported in ci.json. Verification rests on CI evidence only.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
