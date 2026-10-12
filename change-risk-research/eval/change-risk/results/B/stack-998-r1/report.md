## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `e239a73c1f..09ec296f06`

Release-tooling-only fix to scripts/sync-lockstep-versions.mjs, the second half of the root `version` script that release.yml runs via changesets/action. At base, bumpCargoPackageVersion detected a missing version line by checking whether the replace changed anything, so it also threw when the eql-bindings crate was already at the target version. At base and head the crate (3.0.5) already equals @cipherstash/eql's package.json version (3.0.5), so every release that does not bump EQL would have made `pnpm run version` fail after `changeset version` had rewritten manifests, blocking the Version Packages step for all packages. Head tests for the version line explicitly and returns the manifest unchanged when it already matches. The missing-line and missing-section errors are preserved and still unit-tested. No shipped library code, payload format or published artefact contents change. The only newly reachable path is that a non-EQL release now continues into the Cargo.lock refresh and the lockstep skew check; the skew check then skips the SQL rebuild. That path carries a minor risk of unrelated Cargo.lock churn in the release commit. Verification: a new unit test covers the unchanged case. No test result was seen, and no test runs main() end to end with an unchanged version. Advisory verdict: ready for normal review.

### Failure scenarios

**FS-1 · Non-EQL releases now run the Cargo.lock refresh and can commit unrelated lock churn** (low impact, plausible)

- Trigger: A release whose changesets do not bump @cipherstash/eql, made while a committed Cargo.lock that records eql-bindings is out of step with its manifests or with crate registry state.
- Mechanism: At base this path threw before refreshCargoLock (base sync-lockstep-versions.mjs:49-51). At head main() proceeds to `mise exec -- cargo update --package eql-bindings --manifest-path …` for every discovered workspace (head :520-530, :148-168). The script's own comment says `cargo update -p X` re-resolves the whole graph and rewrites a complete lock (head :125-136). Any drift is written into the tree that changesets/action commits as the Version Packages PR.
- Consequence: The Version Packages PR for an unrelated release may carry Cargo.lock edits nobody asked for, or the version step may fail if cargo cannot resolve in the release job. These are visible in the PR diff or as a red job, and are recoverable with a follow-up commit or rerun. Nothing is published with wrong content, and at base this path failed every time anyway.
- Affects: Root `version` script and release.yml changesets/action version step, Cargo.lock files recording eql-bindings by path (packages/eql, packages/protect-ffi)
- Evidence: `scripts/sync-lockstep-versions.mjs:40-53` (base); `scripts/sync-lockstep-versions.mjs:500-534`; `scripts/sync-lockstep-versions.mjs:125-168`
- Existing verification: refreshCargoLock argv is unit-tested with an injected runner, and cargo-lock-freshness.test.mjs fails a PR whose lock drifts (per head comments); neither result was seen. [exists_not_run]
- Missing verification: No test runs main() end to end with npm version equal to the crate version (the exact case this fixes); the main-guard process test uses differing versions and stops at lock discovery.
- Mitigation: Before merging the first Version Packages PR after this lands, check that its Cargo.lock diff is empty when EQL's version did not move. Optionally, skip refreshCargoLock when the crate manifest was unchanged.

### Recommended controls

- Run `pnpm run test:scripts` (scripts/vitest.config.mjs) and confirm sync-lockstep-versions.test.mjs passes, including the new unchanged-version case and the existing missing-line case. (test; VG-1)
- On the next release that does not bump @cipherstash/eql, check that the version step succeeds and the Version Packages PR has no diff under packages/eql/crates/eql-bindings/Cargo.toml, either Cargo.lock, or the EQL release manifests. (review_focus; FS-1)

### What this assessment could not see

- No CI results, release run logs or PR description were available, and node execution of the changed module was not permitted. Test outcomes are unknown. Whether base actually blocked a release is inferred from the code and the equal 3.0.5 versions at base, not observed.
- cargo update behaviour in the release job (network, toolchain, lock drift) was read from in-repo comments, not executed. FS-1 likelihood cannot be estimated. Impact is rated on the mechanism only.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
