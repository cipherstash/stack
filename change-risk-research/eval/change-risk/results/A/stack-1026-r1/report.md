## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `c4ab67ac32..d4a95551a1`

This change is limited to the release pipeline in .github/workflows/release.yml and two new node scripts. First, before `changeset publish` the release job now polls npm until it lists the FFI and auth native packages that publish-ffi and publish-auth have just published. Second, a new eql-assets job decides from npm and the git tags, not from the run's own publish step, whether the EQL SQL, docs and image assets are still owed, and builds them at the commit that the `@cipherstash/eql@<version>` tag names. The four EQL jobs switch to `!cancelled()`. No library code, payload format or SQL changes. The main risk is that the repair path depends on two assumptions about changesets/action that could not be checked here: that it sets `publishedPackages`, and that it pushes the changesets tag, when `changeset publish` exits non-zero. If it does neither, the exact failure this change targets (EQL published and then the publish step fails) leaves eql-assets throwing on every push to main and the assets are still not built. That failure is loud and fails closed, so impact is medium. The unit and workflow-simulation tests are thorough, but they inject these assumptions rather than test them, and none were run.

### Failure scenarios

**FS-1 · A failed `changeset publish` leaves neither publishedPackages nor the changesets tag, so eql-assets throws on every push instead of repairing** (medium impact, plausible)

- Trigger: `changeset publish` publishes @cipherstash/eql@V and then exits non-zero (as in the 3.0.6 run). Or EQL 3.0.6, the tree version at head, has no `@cipherstash/eql@3.0.6` tag in the repository.
- Mechanism: eqlAssets() builds only when `thisRun` (the version is in the run's publishedPackages) or a `@cipherstash/eql@V` tag gives the commit. Otherwise it throws (scripts/eql-release-assets.mjs:91-106). Both sources come from changesets/action, and to my understanding of its implementation (not verifiable offline) it sets the publishedPackages output and pushes tags only after the publish command exits 0. The release job's comment and the tests assert the opposite (release.yml:504-509, eql-release-assets.test.mjs:88-111, 444-459), but they inject that behaviour rather than observe it. eql-assets' own `if` runs it on every production push where gate succeeds (release.yml:669-675), so with npm listing V and no tag of either kind the job errors on each push to main until someone pushes the tag by hand or bumps EQL.
- Consequence: The change does not fix the failure it targets. The EQL SQL release, docs bundle and image for V are still missing, and every release run on main shows a failed eql-assets job, which can hide other release failures. Nothing wrong is published: the script fails closed and tells the operator to push the tag.
- Affects: .github/workflows/release.yml (release, eql-assets, eql-sql, eql-docs, eql-image, eql-summary jobs), scripts/eql-release-assets.mjs, Published EQL GitHub release assets and the postgres-eql image (floating tags)
- Evidence: `scripts/eql-release-assets.mjs:85-114`; `.github/workflows/release.yml:504-509`; `scripts/__tests__/eql-release-assets.test.mjs:70-151`; `.github/workflows/release.yml:620-622` (inferred); `packages/eql/packages/eql/package.json:3`; `.github/workflows/release.yml:669-700`
- Existing verification: Unit tests of eqlAssets(), including a refusal test that expects a throw when no tag names the commit. All inputs are injected (exists_not_run). [exists_not_run]; A workflow-graph simulation in which `release` fails and published_packages is populated. The populated output is an assumption of the simulation. [exists_not_run]
- Missing verification: Confirmation, from the changesets/action v1.9.0 source or from a failed run's job outputs, that publishedPackages is set and tags are pushed when the publish command fails; Confirmation that the tag `@cipherstash/eql@3.0.6` exists in cipherstash/stack before merging, so the first push after merge repairs 3.0.6 rather than failing
- Mitigation: Before merging, check for `refs/tags/@cipherstash/eql@3.0.6` (push it at the publishing commit if it is missing) and check the action's behaviour on failure. Consider letting eql-assets fall back to the commit recorded in npm's provenance (gitHead) or to a manual input, rather than throwing on every push.

**FS-2 · The npm listing wait times out or does not match what changesets reads, which blocks or still fails the JS release** (medium impact, plausible)

- Trigger: npm takes longer than 900 s to list a native package. Or `npm view <name> versions` answers from a cache node that already lists the version while changesets' own `npm info` lookup does not.
- Mechanism: The wait step runs before changesets/action (release.yml:613-618). On timeout it throws and fails the job (wait-for-npm-versions.mjs:82), so `changeset publish` and the Version Packages PR update do not run for that push. Its success means one registry lookup listed the version; it does not guarantee the next lookup, made by changesets, sees the same.
- Consequence: The JS release, including an EQL bump, is held until someone re-runs the job. Or the E402 failure this change was meant to stop happens again. Both are loud and nothing is published wrongly, since the duplicate publish is refused by npm.
- Affects: .github/workflows/release.yml (release, eql-assets, eql-sql, eql-docs, eql-image, eql-summary jobs), scripts/wait-for-npm-versions.mjs, npm publish of JS packages via changesets/action (and the Version Packages PR)
- Evidence: `.github/workflows/release.yml:613-618`; `scripts/wait-for-npm-versions.mjs:24-90`; `scripts/release-gate.mjs:676-689`
- Existing verification: Unit and process tests of waitForVersions: timeout, 404, registry errors, exact-version match and the empty-list fast path (exists_not_run). [exists_not_run]
- Missing verification: No evidence from a real run that the wait closes the window (the change has not yet run against the registry)
- Mitigation: Watch the first FFI or auth release after merge. If E402 recurs, consider a short grace period after the listing appears, or make the native packages ignored by changesets publish.

**FS-3 · Repair builds publish SQL and docs built from an older commit with today's toolchain under an already-released version** (medium impact, speculative)

- Trigger: eql-assets owes the assets for a version published by an earlier run, for example 3.0.6 on the first push after merge, and builds them at the changesets tag commit.
- Mechanism: eql-sql checks out the older ref and runs `mise run --force build --version V` (_build-eql-sql.yml:67,87) using the head revision's reusable workflow. AGENTS.md records that the EQL Rust toolchain is `latest` and that nothing proves regeneration reproduces npm's published bytes (AGENTS.md:487). Before this change the assets were built in the same run as the publish, which narrowed that gap but did not close it.
- Consequence: The GitHub release SQL bundle and the postgres-eql image for V could differ from the SQL inside the npm tarball for V, with nothing reporting it. Or the build fails because the old source does not match the current reusable workflow, which is loud.
- Affects: .github/workflows/_build-eql-sql.yml and _build-eql-docs.yml, Published EQL GitHub release assets and the postgres-eql image (floating tags)
- Evidence: `.github/workflows/_build-eql-sql.yml:60-120`; `AGENTS.md:483-490`; `.github/workflows/release.yml:702-771`
- Existing verification: A test asserts that eql-sql and eql-docs receive eql-assets' ref. Nothing compares the built bundle with the npm tarball. [exists_not_run]
- Missing verification: A digest comparison between the rebuilt SQL bundle and the release-manifest.json in the npm tarball for V before the GitHub release is created
- Mitigation: For repair runs, attach the SQL extracted from the npm tarball, or verify its digest against the published release manifest, rather than rebuilding.

### Recommended controls

- Before merging, confirm that `refs/tags/@cipherstash/eql@3.0.6` exists and points at the commit that published 3.0.6. Confirm from the changesets/action v1.9.0 source, or from the failed 3.0.6 run's outputs, whether publishedPackages and tags are emitted when publish fails. (compatibility_check; FS-1, VG-1)
- Run scripts/__tests__/eql-release-assets.test.mjs, wait-for-npm-versions.test.mjs and workflow-dispatch-job-conditions.test.mjs in CI and attach the results. (test; VG-2)
- Watch the first push to main after merge. Check that eql-assets reports needed=true at the expected ref for 3.0.6, and that eql-sql, eql-docs and eql-image succeed. Watch the next FFI or auth release for a wait timeout or a recurrence of E402. (monitoring; FS-1, FS-2)
- Review the throw in eqlAssets (scripts/eql-release-assets.mjs:99-106). It runs on every push to main, so decide whether persistent red runs are the intended operator signal or whether it should degrade to a warning. (review_focus; FS-1)
- On a repair build, compare the rebuilt SQL bundle's digest with the release manifest in the npm tarball before creating the eql-<version> release. (compatibility_check; FS-3, VG-3)

### What this assessment could not see

- There was no network or GitHub access, so the repository tags, the history of workflow runs, the npm registry and the changesets/action source could not be read. The local checkout has no tags. FS-1 rests on an inferred understanding of changesets/action and on the unknown state of the 3.0.6 tag. It could be a non-issue if both assumptions hold.
- The tests could not be run (no node_modules, no network for an install), and no CI results were provided. Verification confidence is capped at medium even though the tests look thorough.
- release-postgres-eql-image.yml and the internals of the mise build at older refs were not read closely. Whether a repair build of an older ref succeeds with the head revision's reusable workflows is not established.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
