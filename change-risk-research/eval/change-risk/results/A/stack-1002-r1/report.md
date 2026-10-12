## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `c93a39b034..2a38fb4e0d`

Adds two publishing pipelines for the imported @cipherstash/auth napi packages (release.yml auth-artifacts/publish-auth via a new reusable _build-auth-artifacts.yml, plus a manual auth-preflight.yml) and for the stack-auth/stack-profile crates (release-plz.yml release-crates with a new root release-plz.toml). Both are inert at head: the npm jobs only run when the gate reports auth=true, and while the seven auth packages are in FROZEN_PUBLISHERS that state makes the gate exit non-zero first; the crates job is keyed on the same @cipherstash/auth entry. The live behaviour changes today are small: the release gate now classifies auth names separately (auth instead of js), the Release job waits on publish-auth, and release-plz.yml triggers on more paths, which also runs the armed EQL crate job more often. The material risk is latent and lands at the arming PR: the auth musl leg is built without the -crt-static flag the protect-ffi pipeline uses, and neither the release path nor the preflight would catch a statically linked musl binary, so a broken binary could be published irreversibly. Also, once armed, a failure in any of the six auth builds holds every JS release. Static workflow tests were added but not run here (no node_modules, no CI results).

### Failure scenarios

**FS-1 · linux-x64-musl auth binary built statically (no -crt-static) and published without any check that would notice** (high impact, plausible)

- Trigger: The arming PR removes the @cipherstash/auth entries and a version bump makes gate report auth=true, so auth-artifacts builds and publish-auth publishes.
- Mechanism: The musl leg of _build-auth-artifacts.yml installs only musl-tools and runs `napi build --target x86_64-unknown-linux-musl` (lines 68-73, 116). It sets no RUSTFLAGS, and the auth crate's .cargo/config.toml sets flags only for macOS. The protect-ffi pipeline explicitly exports `-C target-feature=-crt-static` for the same target (_build-ffi-artifacts.yml:238) so that the binary links musl dynamically. With Rust's crt-static default on musl, the auth cdylib is either dropped (a loud build failure) or produced self-contained. The release path checks only that a non-empty .node file exists and is in the tarball (lines 131, 163). The manual preflight's musl check only asserts there is NO glibc NEEDED entry (auth-preflight.yml:91-95), which a static binary also satisfies, and the smoke test loads only linux-x64-gnu (line 109).
- Consequence: @cipherstash/auth-linux-x64-musl could ship a .node that fails to load, or crashes, on Alpine/musl hosts. Every stack/CLI install on those hosts would hit 'Failed to load native binding'. npm publishes cannot be undone, so recovery needs a new version of all seven packages.
- Affects: .github/workflows/_build-auth-artifacts.yml, .github/workflows/release.yml (gate, auth-artifacts, publish-auth, release), @cipherstash/auth and @cipherstash/auth-* npm packages (published artefacts)
- Evidence: `.github/workflows/_build-auth-artifacts.yml:68-164`; `.github/workflows/_build-ffi-artifacts.yml:236-238`; `.github/workflows/auth-preflight.yml:84-110`; `languages/typescript/packages/auth/.cargo/config.toml:10-11`
- Existing verification: auth-preflight.yml architecture/libc static check and linux-x64-gnu smoke test (manual dispatch only; the musl check cannot distinguish static from dynamic musl) [exists_not_run]; scripts/__tests__/auth-build-artifacts.test.mjs asserts workflow shape, not binary linkage [exists_not_run]
- Missing verification: A check that the musl binary has a NEEDED entry for libc.musl / ld-musl (a positive assertion, not only the absence of glibc); A load test of the musl tarball in an Alpine container; Evidence of how cipherstash-suite built the published 0.44.0 musl binary, to compare
- Mitigation: Mirror the FFI leg: export RUSTFLAGS='-C target-feature=-crt-static' (and the musl linker) for the musl target. In auth-preflight, require a musl NEEDED entry and smoke-load the musl pair in node:22-alpine. Run auth-preflight against the Version Packages branch before the first armed release.

**FS-2 · Once armed, any auth build failure holds every JS and EQL npm release** (medium impact, plausible)

- Trigger: After arming, a release that bumps the auth group hits a failure in any of the six platform builds or in the wasm/wrapper job (e.g. runner image change, the gate's frozen-bytes or tree-drift checks, wasm-pack/mise download failure).
- Mechanism: publish-auth is skipped when auth-artifacts fails. The Release job requires `needs.gate.outputs.auth != 'true' || needs.publish-auth.result == 'success'` (release.yml:478-482), so changeset publish, the Version Packages PR update and the EQL production chain (eql-sql/eql-docs/eql-image need `release`) all skip. Because changesets uses `fixed` groups, an auth bump can travel in the same Version PR as unrelated packages.
- Consequence: Releases of @cipherstash/stack, stash and @cipherstash/eql are delayed until the auth build is fixed or the auth bump is split out. The design fails closed, so nothing broken ships.
- Affects: .github/workflows/release.yml (gate, auth-artifacts, publish-auth, release), .github/workflows/_build-auth-artifacts.yml
- Evidence: `.github/workflows/release.yml:457-483`; `.github/workflows/release.yml:660-670`
- Existing verification: release-gate.test.mjs asserts the Release job condition holds the release for publish-auth [exists_not_run]
- Missing verification: A dry run of the full auth build on GitHub runners (auth-preflight) before arming
- Mitigation: Run auth-preflight before arming and before every auth release. Release auth bumps in their own Version PR. Document the runbook for a stuck auth build.

**FS-3 · Widened release-plz.yml triggers start the armed EQL crate job on unrelated root-workspace pushes** (low impact, plausible)

- Trigger: A push to main that touches only Cargo.lock, Cargo.toml, release-plz.toml, cliff.toml or the stack-auth/stack-profile crates.
- Mechanism: The new paths sit in the workflow-level `on.push.paths` (release-plz.yml:47-54), so eql-armed and the EQL `release` job (line 86) run as well as crates-armed. The EQL job queries crates.io, and if the eql-bindings version is not on crates.io it enforces the SQL-stamp guard, imports the GPG key and runs release-plz release for packages/eql. The non-cancelling `release-plz` concurrency group serialises the runs.
- Consequence: There are more EQL release runs, each normally a no-op. If an eql-bindings version is left unpublished, it publishes on whichever push comes next, or a crates.io API failure turns an unrelated push red. The failure is visible and recoverable.
- Affects: .github/workflows/release-plz.yml + release-plz.toml + cliff.toml, EQL crate release job in release-plz.yml (`release`)
- Evidence: `.github/workflows/release-plz.yml:44-54`
- Existing verification: eql-pipeline-armed.test.mjs pins that release-crates is the only job gated on crates-armed [exists_not_run]
- Missing verification: No check that the EQL job is scoped to EQL-relevant pushes
- Mitigation: Gate the EQL `release` job on a dorny/paths-filter for packages/eql/**, or split the crates line into its own trigger condition. (The filename is bound by crates.io, so splitting into a new file would need a second Trusted Publishing entry.)

### Recommended controls

- Review the linux-x64-musl leg of _build-auth-artifacts.yml against _build-ffi-artifacts.yml (RUSTFLAGS -crt-static, linker) and against how cipherstash-suite built the published musl binary. (review_focus; FS-1)
- Strengthen auth-preflight: require a musl dynamic-loader NEEDED entry for linux-x64-musl, and smoke-load the musl pair in an Alpine container alongside the gnu one. (test; FS-1, VG-1)
- Before the arming PR, merge this, dispatch auth-preflight against main, and keep the green run as a prerequisite of arming. For the first armed release, bump only the auth group in its own Version PR. (staged_rollout; FS-1, FS-2, VG-2)
- Decide whether the EQL `release` job in release-plz.yml should run on root-workspace pushes, and if not, scope it with a paths filter. (review_focus; FS-3)
- Confirm CI ran the scripts/__tests__ suites (release-gate, eql-pipeline-armed, release-plz-root-config, auth-build-artifacts, auth-repository-urls, lint-release-scope) and lint-release/actionlint on this change. (test; VG-2)

### What this assessment could not see

- No CI results, and the vitest suites could not run locally (no node_modules, no network). Running the modified arming script by hand was not approved in this session. Every test is exists_not_run. Inertness rests on reading release.yml, release-gate.mjs and eql-pipeline-armed.mjs, not on observed runs.
- No view of npm or crates.io trusted-publisher settings, repository secrets (GPG_PRIVATE_KEY), or how cipherstash-suite built the currently published auth binaries. FS-1 rests on comparing this repo's two pipelines and on Rust's documented musl default. Whether the existing published musl binary is dynamic is unknown.
- Read closely: release.yml, release-plz.yml, _build-auth-artifacts.yml, auth-preflight.yml, release-gate.mjs, eql-pipeline-armed.mjs, release-plz.toml, .changeset/config.json and the auth package.json files. Skimmed: cliff.toml, the lint script/test edits, AGENTS.md/CONTRIBUTING.md wording. Changelog formatting and the minor lint edits got only a light review.
- Steps in publish-auth use tag-pinned actions (actions/download-artifact@v4, actions/setup-node@v6.5.0) in a job with id-token: write. This matches the existing publish-ffi job in the same file at base, so it is pre-existing practice rather than something this change introduces. Not raised as a scenario.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
