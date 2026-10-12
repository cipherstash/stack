## Change risk: Ready for normal review

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `e239a73c1f..09ec296f06`

A two-line fix to release tooling. At the base, bumpCargoPackageVersion detected a missing [package] version line by checking whether the replace changed the text, so it also threw when the crate version already equalled the target. The crate and @cipherstash/eql are both at 3.0.5 at head, so every `pnpm run version` that does not bump EQL would have stopped the whole release after `changeset version` had already rewritten the tree. The head checks for the version line directly and returns the manifest unchanged on a no-op, while still throwing when the line is missing. The fix is narrow and correct as read, and the new unit test runs in the `Run Tests (Node 22/24)` CI jobs, which passed. The residual risk is that a no-EQL-bump release now gets past step 2 for the first time and reaches the Cargo.lock refresh and the skew-gated SQL asset step. Those steps are unit-tested with injected runners but have not been run for real on an unchanged version. Any failure there fails closed: the release job stops and needs a fix and a re-run. It cannot publish wrong artefacts. Nothing touches encryption, payloads or published library code.

### Failure scenarios

**FS-1 · First no-EQL-bump release runs the lock-refresh and asset steps for real and stops the release** (medium impact, plausible)

- Trigger: The first stack release after this merges that does not bump @cipherstash/eql (the PR says this is every release after EQL 3.0.6).
- Mechanism: At the base, the throw at step 2 meant steps 3 and 4 had only ever run on releases where the EQL version moved. Now main() continues to cargoLockWorkspaces, `mise exec -- cargo update --package eql-bindings` per workspace (not offline, in a job with a cold registry), and prepareBindingAssets. If any of these misbehaves on an unchanged version, the hook throws or the gate fails closed: a cargo resolution error, a non-empty eqlLockstepSkew from tree skew that triggers a rebuild, or a rebuild whose digest differs and fires frozen-bytes-skew.
- Consequence: The release job fails after `changeset version` has rewritten manifests and changelogs in the CI checkout. No package is published wrongly, but the release is blocked until a fix lands and the job re-runs. This is the same class of outcome the PR removes, now possible one step later.
- Affects: Root `version` script and the release.yml changesets/action `version:` step, eql-bindings crate manifest and the Cargo.lock files that record it by path (packages/eql, packages/protect-ffi), EQL SQL bundle and release manifests (prepareBindingAssets / eqlLockstepSkew)
- Evidence: `scripts/sync-lockstep-versions.mjs:509-534`; `scripts/sync-lockstep-versions.mjs:458-498`; pr_description
- Existing verification: Unit tests in scripts/__tests__/sync-lockstep-versions.test.mjs cover refreshCargoLock argv and prepareBindingAssets skip/rebuild with injected runners. They run under `pnpm run test:scripts` in the Run Tests (Node 22/24) jobs, which passed on head. Per-test results are not visible. [ran_passed]; scripts/__tests__/eql-sql-asset-freshness.test.mjs and cargo-lock-freshness.test.mjs keep the tree free of skew and lock drift at PR time, which is the precondition for step 4 skipping and step 3 being a no-op. [exists_not_run]
- Missing verification: No end-to-end run of `pnpm run version` on a tree where the EQL version is unchanged, with real mise/cargo, has been shown.; No assertion that step 3 leaves Cargo.lock files byte-identical when the eql-bindings version did not move.
- Mitigation: Before the first post-3.0.6 release, run `pnpm run version` locally or in a dry-run job on a branch with a non-EQL changeset, and confirm that it exits 0, that the Cargo.lock files are unchanged and that the log says assets were skipped. Watch the first real release's Version Packages run.

### Recommended controls

- Dry-run `pnpm run version` on a branch carrying only a non-EQL changeset, and check the exit status, `git diff` on the Cargo.lock files and the 'skipping' log line from prepareBindingAssets. (test; FS-1, VG-1)
- Watch the first release after EQL 3.0.6 (the Version Packages run and the release-gate job). The failure mode is loud and fail-closed, so a re-run after a fix is the rollback. (monitoring; FS-1)

### What this assessment could not see

- I could not run node or the vitest suite in this environment (the command needed approval that was not available, and there was no node_modules). The function's behaviour on unchanged, bumped and missing-line inputs was established by reading the code at both revisions. The claim that the fix works rests on code reading plus a passing CI job whose per-step logs I could not see.
- ci.json gives job conclusions only. The claim that `test:scripts` ran comes from the tests.yml step inside the `Run Tests` job, not from a log. ran_passed is inferred at the job level. A skipped or filtered test file would not be visible.
- The cross-repo plan the PR cites (step 7/8 ordering against the EQL 3.0.6 release) and any release history after head are unavailable. I cannot confirm the merge-ordering constraint or whether a non-EQL release is imminent.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
