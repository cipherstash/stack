## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** low · `62e6c4392f..71a2436356`

Builds the release pipeline for @cipherstash/protect-ffi and its six platform packages inside release.yml. A registry-state gate (scripts/release-gate.mjs) now runs on every push to main. If any FFI version is unpublished, a reusable workflow builds the six native binaries and the WASM output, and a publish-ffi job publishes the platform tarballs before the wrapper, then tags them. The change also moves OIDC and write permissions from the workflow level to the publishing jobs and freezes the release install's lockfile. The FFI branch is meant to stay inert at this head: a CI lint blocks FFI changesets, and the committed 0.31.0 is documented as already on npm. I could not check that against the registry. The live effect of merging is therefore mainly that a new gate job stands in front of every JS release. The main latent risk is in the first real FFI publish. The release path checks only that each platform tarball has the right name and contains an index.node. The architecture/libc checks and the load smoke test exist only in the manually dispatched ffi-preflight.yml. So a mis-targeted binary could go to npm, and npm publishes cannot be undone. Every new control has only static unit tests; no run of the publish path has been seen. Advisory: focused review of the publish path before the cutover.

### Failure scenarios

**FS-1 · A mis-targeted native binary can be published, because the release path skips the arch/libc and load checks** (high impact, plausible)

- Trigger: The first real FFI release (after the cutover renames the deferred changesets) has a platform leg whose build emits the wrong architecture or ABI. Examples: a target or toolchain regression on macos-latest (arm64) for darwin-x64, or the musl leg linking glibc.
- Mechanism: _build-ffi-artifacts.yml checks only that each platform tarball has the expected package name and contains package/index.node (lines 278-294). The `file`-based architecture check, the readelf glibc/musl check and the install-and-load smoke test exist only in ffi-preflight.yml (lines 63-151). That workflow is workflow_dispatch-only (lines 17-23) and is not called from release.yml; publish-ffi (release.yml 78-210) uploads whatever ffi-artifacts produced. AGENTS.md says to dispatch the preflight before the cutover, but nothing enforces this on any later release.
- Consequence: A platform package that installs cleanly and then fails to dlopen is published irreversibly with provenance. Every @cipherstash/stack user on that platform cannot load the encryption core until a new version is released. A linux-x64-gnu/musl swap fails only at runtime for Alpine users.
- Affects: .github/workflows/_build-ffi-artifacts.yml, @cipherstash/protect-ffi and six @cipherstash/protect-ffi-<platform> npm packages, .github/workflows/release.yml, .github/workflows/ffi-preflight.yml
- Evidence: `.github/workflows/_build-ffi-artifacts.yml:278-294`; `.github/workflows/ffi-preflight.yml:17-151`; `.github/workflows/release.yml:18-274`; `AGENTS.md:148-158`
- Existing verification: scripts/__tests__/ffi-release-matrix.test.mjs pins each platform's Rust target triple and build script (static unit test) [exists_not_run]; ffi-preflight.yml architecture/libc/smoke checks, run only if someone dispatches it manually [unknown]
- Missing verification: Architecture/libc verification of each index.node inside the publish path itself; A load smoke test of the exact tarballs publish-ffi will upload; Any recorded run of _build-ffi-artifacts.yml producing all seven tarballs
- Mitigation: Move the arch/libc checks (and ideally the host smoke test) from ffi-preflight.yml into _build-ffi-artifacts.yml, so release.yml and the preflight share them, or make publish-ffi depend on them. Run ffi-preflight against the Version Packages branch before the cutover.

**FS-2 · The new gate job is a hard prerequisite for every JS release and Version PR update** (medium impact, plausible)

- Trigger: On a push to main, any `npm view` call fails with something other than E404: a registry or network error, rate limiting, or npm CLI output that does not contain the string E404. Alternatively, the registry does not actually hold all seven FFI packages at 0.31.0.
- Mechanism: release-gate.mjs throws on any non-404 lookup error (lines 149-161) and runs about 10 lookups per push. The release job requires `needs.gate.result == 'success'` (release.yml 225-231), so the changesets job, which opens and updates the Version PR and publishes JS, does not run. If the 0.31.0 assumption (lint-no-ffi-changeset.mjs:33) is wrong, ffi=true on merge, and publish-ffi fails because the trusted publisher still names protectjs-ffi. The release job is then skipped on every push until that is fixed.
- Consequence: JS releases stall loudly; no binary-less publish happens. Recovery is a re-run in the transient case. If the FFI branch fires early, it needs a cutover or an FFI-version fix before Stack can release again.
- Affects: scripts/release-gate.mjs, .github/workflows/release.yml, @cipherstash/stack, stack-drizzle, stack-supabase (and the Stack fixed group), npm trusted-publisher configuration for the seven FFI packages
- Evidence: `scripts/release-gate.mjs:42-181`; `.github/workflows/release.yml:18-274`; `scripts/lint-no-ffi-changeset.mjs:33-43` (inferred)
- Existing verification: release-gate.test.mjs covers 404-as-unpublished, error propagation, private-skip and classify (unit, with stubbed lookups) [exists_not_run]
- Missing verification: Confirmation that every FFI package is on npm at 0.31.0 (registry not accessible here); A real run of the gate against the registry before merge
- Mitigation: Before merging, run `node scripts/release-gate.mjs` locally and check that it prints ffi=false. Consider retrying transient npm view failures inside the gate, keeping the fail-closed behaviour on persistent errors.

**FS-3 · Partial FFI release: npm packages published but tags, release or the dependent Stack publish missing** (low impact, plausible)

- Trigger: During an FFI release, the `Tag and release` step fails after the npm publishes (GitHub API error, or a tag at another commit). Or the wrapper publish fails after some platform packages are already published.
- Mechanism: publish-ffi publishes to npm first (release.yml 121-154) and tags afterwards (160-210). A tag-step failure marks publish-ffi as failed, and `release` is then skipped (225-231). The new protect-ffi version is on npm, but the Stack packages that should consume it are not published, and there is no tag or GitHub release. Re-runs are designed to be idempotent: npm view skip, tag-at-same-commit skip, upload --clobber.
- Consequence: Registry and git disagree until someone re-runs the workflow. Users can install the new protect-ffi on its own. Loud and recoverable.
- Affects: .github/workflows/release.yml, @cipherstash/protect-ffi and six @cipherstash/protect-ffi-<platform> npm packages, @cipherstash/stack, stack-drizzle, stack-supabase (and the Stack fixed group)
- Evidence: `.github/workflows/release.yml:18-274`
- Existing verification: No test exercises the publish-ffi shell steps; actionlint/shellcheck lint them statically [unknown]
- Missing verification: A rehearsal of a re-run after a partial failure
- Mitigation: Document the re-run procedure for the cutover. Watch the first FFI release run to completion.

### Recommended controls

- Run the architecture/libc verification (and the host smoke install) inside _build-ffi-artifacts.yml, so every publish enforces it rather than only the manual preflight. (test; FS-1, VG-1)
- Before merging, confirm on npm that all seven FFI packages exist at 0.31.0, and run the gate script read-only to confirm it prints ffi=false. (compatibility_check; FS-2, VG-2)
- Review release.yml: the `release` job's `if:` expression, the job-level permission grants, and the publish-ffi ordering, idempotency and tag logic. (review_focus; FS-2, FS-3)
- For the cutover: dispatch ffi-preflight on the Version Packages branch, watch the first FFI release, and have a re-run and deprecate-and-republish plan ready, since npm publishes cannot be undone. (rollback_plan; FS-1, FS-3)

### What this assessment could not see

- No network: npm registry state, trusted-publisher configuration and GitHub settings were not observable. I could not confirm that the FFI branch is inert at merge (FS-2), and I could not check the publish auth.
- I could not run tests. node_modules is absent, and running node required approval that was not available, so no vitest suite was executed. Every verification is exists_not_run; verification confidence is low.
- I read release.yml, release-gate.mjs, ffi-release-matrix.mjs, _build-ffi-artifacts.yml, ffi-preflight.yml and lint-release.yml closely. I skimmed the lint-no-workflow-caching changes, the new script tests, the e2e supply-chain test, the plan doc and the skill text, and did not read them line by line. Subtle defects in the test logic or in the customer-facing skill wording may be missed.
- There is no PR description or CI results. Behaviour of GitHub Actions (always()/skipped semantics, reusable-workflow permission inheritance) and of npm provenance was judged from general knowledge and the in-file comments. The analysis of the job-condition and permission changes is unconfirmed by any run.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
