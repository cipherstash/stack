## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `c806cfd83c..37c32967ba`

Ports the EQL release workflows from the dead packages/eql/.github/ deposit to the repo root, merged into the shared release.yml, kept inert behind FROZEN_PUBLISHERS. The EQL publishing jobs do not run today. The material risk is in the shared, live release workflow: release.yml gains workflow_dispatch, and a new `classify` job decides 'production' from GITHUB_REF_NAME == 'main'. That is a short ref name, so a dispatch against a tag named `main` would classify as production and run the OIDC-holding FFI/JS publish jobs on an unreviewed commit. Nothing tests the classify shell logic. Once armed, the prerelease path authorises on a commit-subject marker on any branch. Its SQL and docs release assets are rebuilt independently of the bundle shipped in npm, and the npm publish precedes the never-executed SQL/docs/image jobs. Guard and lint hardening (cache bans, stamp-based SQL verification, permission split) is well tested and CI is green.

### Failure scenarios

**FS-1 · Dispatch against a non-branch ref named `main` classifies as production and publishes npm packages from an unreviewed commit** (high impact, plausible)

- Trigger: Someone with write access creates a tag (or other non-branch ref) named `main` on an unreviewed commit and dispatches release.yml against refs/tags/main, deliberately or by ref ambiguity.
- Mechanism: classify sets branch="${GITHUB_REF_NAME}" and mode=production when it equals 'main' (release.yml:79-85). GITHUB_REF_NAME is the short name of the branch or tag that triggered the run, so refs/tags/main also yields 'main'. ffi-artifacts, publish-ffi and release key only on mode == 'production' plus the registry gate (release.yml:199, 207, 358). They then check out github.sha and run npm publish / changeset publish with id-token: write. Before this change release.yml had no workflow_dispatch trigger, so only a push to main (normally branch-protected) could reach these jobs.
- Consequence: JS or FFI package versions committed on that tree but not yet on npm are published from code that never passed review. They carry valid npm provenance naming cipherstash/stack and release.yml. npm publishes are irreversible, so this is a supply-chain integrity breach for every consumer of those packages.
- Affects: .github/workflows/release.yml (JS + FFI + EQL release), npm packages published by release.yml (@cipherstash/stack, protect-ffi wrapper + 6 platform packages, etc.)
- Evidence: `.github/workflows/release.yml:43`; `.github/workflows/release.yml:79-91`; `.github/workflows/release.yml:343-371`; `scripts/__tests__/workflow-dispatch-job-conditions.test.mjs:86-99`
- Existing verification: workflow-dispatch-job-conditions.test.mjs evaluates job `if:` conditions only against a synthetic dispatch on refs/heads/main. It does not execute or model the classify shell logic or a tag ref. [ran_passed]
- Missing verification: A test that drives the classify step (or an extracted script) with a tag ref, a non-main branch and main, and asserts that only refs/heads/main yields production.; Confirmation of repository rulesets: tag-creation protection for `main`, and who may dispatch workflows.
- Mitigation: Decide production from the full ref (GITHUB_REF == 'refs/heads/main', or a job-level `if: github.ref == 'refs/heads/main'` on the publishing jobs), and consider requiring github.event_name == 'push' for production. Optionally bind npm trusted publishing to a protected GitHub environment.

**FS-2 · After arming, any writer can publish an EQL prerelease (npm, crate, SQL release) from an unreviewed branch** (high impact, plausible)

- Trigger: After the Phase-5 cutover removes @cipherstash/eql from FROZEN_PUBLISHERS, a collaborator pushes any branch whose HEAD subject starts with `chore(release):` and pins an X.Y.Z-(alpha|beta|rc).N version, then dispatches release.yml (or dispatches release-plz.yml / release-postgres-eql-image.yml directly on any ref).
- Mechanism: classify sets mode=prerelease for any non-main ref whose last commit subject matches chore\(release\):* (release.yml:84-91). The only further checks are the version regex and the tag-exists short-circuit. prerelease-eql-npm then runs npm-publish.mjs with id-token: write. prerelease-eql-crate force-updates release/eql-<V> to the run's sha and dispatches release-plz.yml, which publishes the crate over OIDC (release.yml:756-786, release-plz.yml:44,75-85). The PR states the safety is 'the marker commit, the version regex and the tag short-circuit — not the branch name'.
- Consequence: Unreviewed SQL and bindings reach npm (alpha/beta/rc dist-tag), crates.io and a GitHub release. Users who opt into prereleases install them into their databases, and the publishes cannot be retracted. Inert until the cutover, but the cutover only deletes a map entry, so nothing forces this boundary to be revisited then.
- Affects: .github/workflows/release.yml (JS + FFI + EQL release), @cipherstash/eql npm package (packages/eql/packages/eql), eql-bindings crate (release-plz.yml), EQL SQL / docs GitHub releases and ghcr.io postgres-eql image
- Evidence: `.github/workflows/release.yml:79-91`; `.github/workflows/release.yml:642-786`; `.github/workflows/release-plz.yml:26-85`; pr_description; `AGENTS.md:355-363`
- Existing verification: eql-pipeline-armed.test.mjs checks that every EQL publish job is gated on eql-armed (inertness), not who may trigger it. [ran_passed]
- Missing verification: No control or test restricts the prerelease path to protected refs or approved actors.; Cutover checklist does not mention constraining dispatch of release.yml / release-plz.yml / image workflow.
- Mitigation: Before arming, restrict prerelease dispatch to a protected ref pattern (e.g. release/** under a ruleset) or a protected GitHub environment with required reviewers. Apply the same restriction to release-plz.yml and release-postgres-eql-image.yml dispatch. Add this to the Phase-5 cutover checklist.

**FS-3 · First armed production run publishes npm before the never-executed SQL/docs/image jobs, leaving a partial EQL release** (medium impact, plausible)

- Trigger: The first production EQL release after the cutover, where _build-eql-sql.yml, _build-eql-docs.yml or the image dispatch fails (path, runner, permission, GHCR ownership or missing secret).
- Mechanism: eql-sql, eql-docs and eql-image need `release`, which has already run changeset publish (release.yml:541-600). release-plz.yml publishes the crate independently on the same push. None of the armed jobs can run before the cutover. The PR says the docs workflow 'still needs its first execution in this repository', and AGENTS.md lists GHCR write access and GPG_PRIVATE_KEY as unmet cutover prerequisites.
- Consequence: @cipherstash/eql V is on npm while the eql-V SQL release, docs bundle, crate or image is missing or late, and the lockstep five-artefact promise is broken. It can be recovered by re-running, and the failure is loud, but the npm half cannot be undone.
- Affects: .github/workflows/release.yml (JS + FFI + EQL release), @cipherstash/eql npm package (packages/eql/packages/eql), EQL SQL / docs GitHub releases and ghcr.io postgres-eql image
- Evidence: `.github/workflows/release.yml:541-600`; pr_description; `AGENTS.md:355-363`
- Existing verification: actionlint over the new release workflows passed in CI. [ran_passed]; Static workflow tests (eql-suite-ci, eql-pipeline-armed, workflow-publish-permissions) passed as part of test:scripts. [ran_passed]
- Missing verification: No dry run of the armed SQL/docs/image/crate jobs in this repository (e.g. a dispatch with a test tag on a fork or with publish disabled).
- Mitigation: Before the cutover, rehearse the armed chain without registry publishes (attach=false SQL/docs builds, image build with push: false), confirm GHCR/GPG/crates.io prerequisites, and keep a runbook for re-running eql-sql/docs/image against an already-published version.

**FS-4 · GitHub-release and image SQL rebuilt from source can differ in bytes from the bundle shipped in npm under the same version** (medium impact, speculative)

- Trigger: An armed release where the toolchain at release time (packages/eql/mise.toml pins rust = latest) produces SQL differing from the bundle committed by the version hook.
- Mechanism: _build-eql-sql.yml runs `mise run --force build --version` on a fresh runner and uploads release/cipherstash-encrypt.sql (lines 80-124). The image workflow does its own unforced build (line 100). Neither compares the result to the committed release-manifest digests that the npm tarball and crate ship. AGENTS.md states that nothing proves regenerating from in-tree source reproduces published bytes.
- Consequence: Customers installing from the eql-V GitHub release or the postgres-eql:V image can get SQL that differs from what @cipherstash/eql@V and eql-bindings V install, under an identical version stamp. Wrong behaviour of this kind can go unnoticed for a long time.
- Affects: @cipherstash/eql npm package (packages/eql/packages/eql), EQL SQL / docs GitHub releases and ghcr.io postgres-eql image
- Evidence: `.github/workflows/_build-eql-sql.yml:80-124`; `.github/workflows/release-postgres-eql-image.yml:56-100`; `packages/eql/mise.toml:11`
- Existing verification: eql-sql-asset-freshness.test.mjs checks in-tree lockstep and that the release build uses --force. It does not compare release-time builds to committed digests. [ran_passed]
- Missing verification: No step compares the release-built SQL digest against the committed sql/release-manifest.json for that version.
- Mitigation: Attach the committed, manifest-verified bundle to the GitHub release (and COPY it into the image) instead of rebuilding, or add a digest-equality check against the committed manifest before attaching or pushing.

**FS-5 · Removing the live root rebuild-docs.yml stops docs-site rebuilds on @cipherstash/stack releases if the webhook is still in use** (low impact, speculative)

- Trigger: A @cipherstash/stack release after merge, while DOCS_WEBHOOK_URL still drives a live docs deployment.
- Mechanism: The base root workflow POSTed secrets.DOCS_WEBHOOK_URL on every @cipherstash/stack@* tag push. It is deleted, and a new test forbids any workflow from referencing the secret. The PR and docs assert the site is retired. That cannot be verified from the inputs.
- Consequence: Docs are not rebuilt after stack releases. This is low impact and recoverable by a manual rebuild.
- Affects: External docs site rebuilt via DOCS_WEBHOOK_URL
- Evidence: `.github/workflows/rebuild-docs.yml:1-17` (base); `scripts/__tests__/eql-suite-ci.test.mjs:1431-1440`
- Missing verification: Confirmation from the docs-site owner that the webhook is unused.
- Mitigation: Confirm with the docs owner before merge, and delete the DOCS_WEBHOOK_URL secret if it is truly retired.

### Recommended controls

- Replace the GITHUB_REF_NAME == 'main' test in classify with a full-ref check (refs/heads/main), or add `github.ref == 'refs/heads/main'` to the ffi-artifacts, publish-ffi and release `if:` conditions. (review_focus; FS-1)
- Extract classify into a script (like eql-pipeline-armed.mjs) and test tag refs, non-main branches with and without the marker, malformed versions and an existing tag. (test; FS-1, VG-1)
- Before arming, require a protected environment or protected ref ruleset for the prerelease path and for dispatch of release-plz.yml and release-postgres-eql-image.yml, and add this to the Phase-5 cutover checklist. (other; FS-2)
- Rehearse the armed SQL/docs/image/crate chain without publishing before the cutover, and document re-run steps for a partial EQL release. (staged_rollout; FS-3, VG-2)
- Ship the committed, manifest-verified SQL in the GitHub release and image, or assert digest equality before attaching or pushing. (compatibility_check; FS-4, VG-3)
- Confirm with the docs owner that DOCS_WEBHOOK_URL is unused before deleting the stack rebuild-docs workflow. (documentation; FS-5)

### What this assessment could not see

- Repository settings (rulesets, tag protection, who can dispatch workflows, environments) and registry trusted-publisher constraints were unavailable. Whether FS-1 and FS-2 are reachable in practice depends on settings that could not be seen. They are rated by mechanism.
- Read closely: release.yml diff and head, release-plz.yml, _build-eql-sql.yml, the image build-sql job, eql-pipeline-armed.mjs, the release-gate.mjs header, verify-release-assets/npm-publish diffs, linter diffs, and parts of the workflow tests. Skimmed or not read: _build-eql-docs.yml, the image push/floating-tag jobs, most of the eql-suite-ci.test.mjs and cargo-publish-opt-out test changes, and the AGENTS/SECURITY/plan doc edits. Defects in the skimmed workflows (e.g. image tag policy) may be missed.
- No node_modules was available and no tests were run locally. Test results come only from ci.json check names, and the mapping of test:scripts to 'Run Tests (Node 22/24)' was read from tests.yml:295-296. Per-test pass status is inferred from job-level success.
- The release-gate summary comment in eql-summary says the gate exits non-zero for a frozen publisher as the 'NORMAL inert state'. AGENTS.md says it fails only on three specific conditions. Which is true for the current registry state was not checked (it needs network). If the gate currently fails on every push, JS releases are already blocked independently of this change. That was not assessed.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
