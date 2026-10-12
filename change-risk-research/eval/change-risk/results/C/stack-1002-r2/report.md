## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `c93a39b034..2a38fb4e0d`

This change adds release jobs that publish @cipherstash/auth (the wrapper plus six native platform packages) to npm and stack-auth/stack-profile to crates.io. It also adds an auth flag to the release gate. Merged as it stands, it is inert. The npm auth jobs need gate.outputs.auth == 'true' and a successful gate, which cannot both hold while the seven auth packages are frozen. The crates job runs only once the @cipherstash/auth freeze entry is removed. CI tests that check this gating ran and passed. The material risk comes later, at arming (PR E). The publishing path only checks that each platform binary is present; the architecture and smoke checks are only in a manual preflight that has not run in the supplied CI. One freeze entry also arms both the npm and crates.io lines. For releases today, merging this alone changes little: the release job also waits on a skipped publish-auth, and release-plz.yml triggers on more paths.

### Failure scenarios

**FS-1 · First armed run publishes an auth platform package whose binary is wrong or unloadable** (high impact, plausible)

- Trigger: PR E, or any later edit, removes the @cipherstash/auth entries from FROZEN_PUBLISHERS while an auth version bump is on main, and auth-preflight was not run on that exact ref.
- Mechanism: On the publishing path, _build-auth-artifacts.yml only checks that each platform tarball has the right name and contains a stack-auth-node.<platform>.node file. The architecture and libc checks and the install smoke test exist only in the manual auth-preflight.yml, which release.yml neither calls nor requires. This build workflow has not run in any supplied CI, so its first real execution may be a live publish. The cross-target legs are the likeliest to produce a binary that is present but wrong: darwin-x64 on an arm64 macOS runner, and linux-x64-musl on a glibc host with musl-tools.
- Consequence: A platform package is published with a binary that does not load because of the wrong architecture or libc. Customers on that platform get a load failure from @cipherstash/auth. An npm version cannot be republished, so the fix needs a new release.
- Affects: _build-auth-artifacts.yml (reusable build), Published npm packages @cipherstash/auth and @cipherstash/auth-<platform> (x6), release.yml (Release JS): auth jobs and the release job
- Evidence: `.github/workflows/_build-auth-artifacts.yml:145-164`; `.github/workflows/auth-preflight.yml:15-118`; `.github/workflows/release.yml:350-447`; `read ci.json (supplied input)`
- Existing verification: Static tests on the build workflow: --js false, the clean-tree check, the wrapper packed with pnpm, and every platform built [ran_passed]; The architecture, libc and smoke checks in auth-preflight.yml (manual dispatch only) [exists_not_run]
- Missing verification: No supplied CI run executes _build-auth-artifacts.yml or auth-preflight.yml; No binary other than linux-x64-gnu is load-tested on its own platform; The publishing path has no architecture check
- Mitigation: Before PR E arms the line, run auth-preflight on the ref to be released. Better, have release.yml run the same file/readelf architecture checks on auth-tarballs before publish-auth, so the guard does not depend on someone remembering a manual step.

**FS-2 · One switch arms npm auth publishing and crates.io publishing together** (medium impact, plausible)

- Trigger: The @cipherstash/auth entries are removed from FROZEN_PUBLISHERS, either on purpose in PR E or as a side effect of another edit.
- Mechanism: crates-armed reads the @cipherstash/auth entry because no crate has its own entry, so removing it arms release-crates as well as the npm auth jobs. Unlike the npm line, the crates line has no frozen-bytes check. release-plz release publishes any root-workspace crate whose in-tree version is not on crates.io. Its preflight only decides whether to import the GPG key.
- Consequence: If crates.io lacks the in-tree stack-auth/stack-profile version 0.42.3, or a hand bump is already on main, arming publishes the imported source to crates.io at once, and the publish is irreversible. If crates.io Trusted Publishing has not been repointed yet, the job fails loudly instead.
- Affects: release-plz.yml crates.io workflow (EQL and stack-* lines), Published crates stack-auth and stack-profile (crates.io), scripts/eql-pipeline-armed.mjs (publisher switch), Published npm packages @cipherstash/auth and @cipherstash/auth-<platform> (x6)
- Evidence: `scripts/eql-pipeline-armed.mjs:44-73`; `.github/workflows/release-plz.yml:191-263`; `Cargo.toml:7-17`; pr_description (inferred)
- Existing verification: eql-pipeline-armed tests check that the crates line keys on @cipherstash/auth and gates exactly release-crates. The release-plz-root-config test checks that only the two crates release. [ran_passed]
- Missing verification: I could not check whether crates.io has stack-auth/stack-profile 0.42.3 (no network); No test checks that arming the crates line is a no-op when the versions are already published
- Mitigation: In PR E, before deleting the entry, confirm that crates.io already has the in-tree versions and that Trusted Publishing names cipherstash/stack and release-plz.yml. Consider a separate arming key for the crates line.

**FS-3 · A failing auth build holds every JS release on main** (medium impact, plausible)

- Trigger: After arming, an auth version is unpublished and auth-artifacts or publish-auth fails, for example after a runner image change, a cross-compile failure, or with no npm trusted publisher configured.
- Mechanism: The release job requires publish-auth to succeed whenever gate.outputs.auth == 'true'. That same job opens and updates the Version Packages PR and runs changeset publish for every other package.
- Consequence: The release fails closed. Nothing else publishes (stack, stash, protect-ffi) and the Version Packages PR is not updated until auth is fixed or the freeze is restored. The failure is loud and recoverable.
- Affects: release.yml (Release JS): auth jobs and the release job, Ordinary JS releases (changeset publish, Version Packages PR)
- Evidence: `.github/workflows/release.yml:457-482`; `.github/workflows/release.yml:350-447`
- Existing verification: A release-gate test asserts that the release job waits for publish-auth [ran_passed]
- Missing verification: No dry run of the full release.yml auth path
- Mitigation: This fail-closed behaviour is intended. Run auth-preflight before arming so the first armed run is unlikely to fail, and document the revert path: restore the freeze entries.

**FS-4 · Wider release-plz path filter starts the armed EQL publish job on root Cargo changes** (low impact, plausible)

- Trigger: A push to main touches only Cargo.lock, Cargo.toml or the stack-* crates while an eql-bindings version bump on main is unpublished.
- Mechanism: The push path filter applies to the whole workflow, not to each job. The EQL release job is armed, so it now also runs on these paths.
- Consequence: The EQL release can publish on a push unrelated to EQL. It runs the same guarded, idempotent release that the next EQL push would run, so mainly the timing changes. With nothing pending, the extra runs do nothing.
- Affects: EQL crates.io release line (eql-bindings), release-plz.yml crates.io workflow (EQL and stack-* lines)
- Evidence: `.github/workflows/release-plz.yml:46-54`; `.github/workflows/release-plz.yml:65-167`
- Existing verification: The workflow-paths-filter-parity test was updated for the new paths [ran_passed]
- Mitigation: Accept this, or move the stack-* line into its own workflow file if separate triggers matter. Note that crates.io binds the publisher to the filename.

### Recommended controls

- Reviewers should confirm that the auth jobs in release.yml (lines 350-447) have no always() and are therefore skipped when the gate fails, and that the release-job condition (lines 457-482) still passes when publish-auth is skipped. (review_focus; FS-3)
- Dispatch auth-preflight.yml on this head, and again on the release ref before PR E. Keep both runs as evidence. (test; FS-1, VG-1)
- Run the auth-preflight architecture and libc checks inside release.yml or _build-auth-artifacts.yml, before publish-auth, so that no publish relies on a manual step. (other; FS-1, VG-2)
- Before PR E, confirm that crates.io already has the in-tree stack-auth/stack-profile versions, and that the crates.io and npm trusted publishers name cipherstash/stack and the right workflow files. (compatibility_check; FS-2, VG-3)
- Document how to disarm: restoring the seven FROZEN_PUBLISHERS and FROZEN_ARTEFACT_DIGESTS entries disarms both lines. A version that is already published needs a new release or npm deprecate. (rollback_plan; FS-1, FS-2, FS-3)

### What this assessment could not see

- With no network, I could not check npm and crates.io registry state, trusted-publisher configuration or the GitHub secrets (GPG_PRIVATE_KEY). It is unknown whether arming does nothing or triggers an immediate publish (FS-2).
- ci.json has conclusions only. I inferred which tests ran inside 'Run Tests (Node 22/24)' from tests.yml at head, which runs test:scripts and release:gate in that job. The ran_passed status for the script tests depends on that mapping.
- I read the release workflows, the gate, the armed script, release-plz.toml, the Cargo manifests and the auth manifests closely. I skimmed the test files, and the AGENTS.md, CONTRIBUTING.md, cliff.toml and lint-script changes. Documentation and changelog-template issues (for example, cliff.toml output) are not assessed.
- The PR is stacked on #1003 and is followed by PR E. I assessed only this base..head range. FS-1 to FS-3 would happen in PR E, and I have not seen that PR's controls.
- I could not run the script tests locally: node_modules is absent and installing it needs the network. The test results rest only on the supplied CI.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
