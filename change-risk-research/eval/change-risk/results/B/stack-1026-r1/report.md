## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `c4ab67ac32..d4a95551a1`

Release-pipeline-only change to .github/workflows/release.yml plus two new node-builtin scripts. (1) The `release` job now waits, for up to 15 minutes, until `npm view <pkg> versions` lists every package that publish-ffi and publish-auth exported, before `changeset publish` runs. This targets the E402 re-publish failures. (2) The production EQL asset chain (eql-sql/docs/image) no longer keys on outputs of a step after `changeset publish`. A new `eql-assets` job runs on every production push. It asks npm whether the tree's EQL version is published and whether the `eql-<version>` tag exists, then builds at the commit named by the `@cipherstash/eql@<version>` changesets tag, or at this run's commit when this run published it. The jobs switch from the implicit success() to `!cancelled()` with explicit result checks. No library code, payload format or customer-facing package content changes. The main residual risk is that the repair path depends on things the change asserts but cannot show: that changesets/action exports publishedPackages and pushes its tags even when `changeset publish` fails, and that a `@cipherstash/eql@3.0.6` tag exists. If either assumption is false, eql-assets fails closed with an error on pushes to main, and the motivating 3.0.6 assets are still not built automatically. Failures are loud and do not block npm publishing. Impact is medium. Extensive vitest suites exist but were not run (vitest is not installed and there is no network).

### Failure scenarios

**FS-1 · Repair path relies on changesets/action outputs and tags surviving a failed `changeset publish`** (medium impact, plausible)

- Trigger: `changeset publish` publishes @cipherstash/eql and then exits non-zero (the 3.0.6 E402 case). Also the existing 3.0.6 state, on the first production push after merge, if no `@cipherstash/eql@3.0.6` tag was ever pushed.
- Mechanism: eql-assets builds only if this run's publishedPackages names EQL, or if the `@cipherstash/eql@<version>` tag exists (eql-release-assets.mjs:91-105). The workflow comment asserts that changesets/action sets publishedPackages even when `changeset publish` fails. If the action instead sets outputs and pushes tags only after the publish command succeeds, a failed publish gives thisRun=false and no changesets tag. eql-assets then reports 'not on npm' if npm has not listed the version yet, or throws 'no … tag says which commit published it' once npm lists it. This repeats on every subsequent production push until someone pushes the tag by hand. The tree is at 3.0.6 (packages/eql/packages/eql/package.json), the version described as on npm with no tag or release.
- Consequence: The automatic repair this change is meant to provide does not happen. EQL SQL, docs and image assets stay missing, and release.yml shows a failing eql-assets job on every push to main until there is manual intervention. npm publishing and the Version Packages PR are unaffected. The failure is loud and fails closed, with no wrong artefact.
- Affects: .github/workflows/release.yml (release, publish-ffi, publish-auth, eql-* jobs), scripts/eql-release-assets.mjs and scripts/wait-for-npm-versions.mjs, GitHub release eql-<version> (SQL install bundle), docs bundle and postgres-eql image
- Evidence: `scripts/eql-release-assets.mjs:86-113`; `scripts/eql-release-assets.mjs:99-105`; `.github/workflows/release.yml:504-509`; `scripts/__tests__/eql-release-assets.test.mjs:444-459`; `packages/eql/packages/eql/package.json`
- Existing verification: eql-release-assets.test.mjs simulates 'runs them when `changeset publish` fails' with a non-empty publishedPackages fixture, and refuses a version that has no changesets tag. The fixture assumes the action's behaviour and does not verify it. [exists_not_run]
- Missing verification: Confirmation, from changesets/action v1.9.0 source or a past failed run, that publishedPackages is set and tags are pushed when the publish command exits non-zero; Confirmation that tag `@cipherstash/eql@3.0.6` exists in cipherstash/stack
- Mitigation: Before merge, check whether the `@cipherstash/eql@3.0.6` tag exists. If it does not, push it at the publishing commit, or build 3.0.6's assets by hand. Check changesets/action's failure-path outputs, and if they are not set, correct the workflow comment and the AGENTS.md claim.

**FS-2 · npm listing lag beyond 15 minutes blocks every JS release in that run** (low impact, plausible)

- Trigger: An FFI or auth release where npm's packument takes longer than 900 s to list a version, or `npm view` errors persistently, for example during a registry incident.
- Mechanism: waitForVersions throws at the deadline and the step fails before `changeset publish` (wait-for-npm-versions.mjs:77-89), so the release job publishes no JS packages and does not update the Version Packages PR. Errors are retried rather than surfaced early.
- Consequence: The release is delayed until someone re-runs the job. Nothing is published twice or published partially by this step. This is a loud, recoverable outcome and is strictly better than the base's E402 failure after a partial publish.
- Affects: .github/workflows/release.yml (release, publish-ffi, publish-auth, eql-* jobs), npm packages @cipherstash/protect-ffi*, @cipherstash/auth* and all changesets-published JS packages
- Evidence: `scripts/wait-for-npm-versions.mjs:48-91`; `scripts/wait-for-npm-versions.mjs:24-25`
- Existing verification: wait-for-npm-versions.test.mjs covers timeout, 404 handling, retried errors, exact-version matching and the process exit with an npm shim. [exists_not_run]
- Mitigation: Accept the risk. The error message already tells the operator to re-run.

**FS-3 · Repair rebuild runs head's reusable workflow against an older source tree** (medium impact, speculative)

- Trigger: eql-assets repairs an older EQL version (ref ≠ github.sha) after the build tooling under packages/eql has changed between that commit and head.
- Mechanism: `uses: ./.github/workflows/_build-eql-sql.yml` resolves at the run's commit, but the job checks out `inputs.ref` (the older publishing commit) and runs `mise run --force build --version` from that tree. The mise version, task names or release paths at head may not match the old tree.
- Consequence: Most mismatches fail loudly (if-no-files-found: error). A silent difference in the SQL bundle compared with the npm tarball is possible only if the build is not deterministic across tool versions. That is unverified.
- Affects: .github/workflows/_build-eql-sql.yml / _build-eql-docs.yml (reusable), GitHub release eql-<version> (SQL install bundle), docs bundle and postgres-eql image
- Evidence: `.github/workflows/_build-eql-sql.yml:64-122`; `scripts/eql-release-assets.mjs:99-105`
- Missing verification: A digest comparison between the repaired SQL bundle and the one inside the npm tarball for the same version
- Mitigation: For the first repair (3.0.6), compare the attached cipherstash-encrypt.sql against the npm tarball's copy before announcing it.

### Recommended controls

- Reviewer: confirm from changesets/action v1.9.0 whether `publishedPackages` is set and tags are pushed when the publish script exits non-zero. Correct the release.yml comment (lines 504-507) and AGENTS.md if it is not. (review_focus; FS-1, VG-1)
- Before merge, check for the `@cipherstash/eql@3.0.6` tag. If it is absent, push it at the 3.0.6 publishing commit, so the first push after merge repairs 3.0.6 instead of failing eql-assets on every push. (rollback_plan; FS-1)
- Run the vitest suites for eql-release-assets, wait-for-npm-versions and workflow-dispatch-job-conditions in CI, and check the result before merge. (test; VG-2)
- After the first automatic repair, diff the attached SQL bundle against the npm tarball's bundle for that version. (compatibility_check; FS-3, VG-3)

### What this assessment could not see

- There was no access to npm, the GitHub tags and releases, or past workflow runs, so the existence of `@cipherstash/eql@3.0.6` and `eql-3.0.6` could not be checked. FS-1's trigger for the first post-merge run cannot be confirmed or ruled out.
- changesets/action behaviour on a failed publish is inferred from the assessor's knowledge of the action, not from source read in this environment. FS-1 stays plausible_failure, not observed_defect.
- The workflow-dispatch-job-conditions.test.mjs refactor (-265 lines moved to scripts/__tests__/lib/expressions.mjs) and the expression evaluator were skimmed, not read line by line. A weakening of existing condition tests caused by the refactor could have been missed.
- GitHub Actions semantics, such as job outputs being evaluated from a failed job, and `!cancelled()`, were taken from documentation knowledge and the in-repo expression simulator, not observed in a live run. Condition-level correctness rests on unrun simulation tests.

_Inputs unavailable: ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
