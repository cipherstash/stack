## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `c93a39b034..2a38fb4e0d`

PR D of the stack crates import adds, switched off, the pipelines that will publish @cipherstash/auth with its six napi platform packages to npm (release.yml auth-artifacts/publish-auth via the new reusable _build-auth-artifacts.yml) and stack-auth/stack-profile to crates.io (release-plz.yml crates-armed/release-crates), plus a manual auth-preflight.yml dry run. The release gate gains a separate `auth` flag so an unpublished auth version no longer reads as `js`. The inertness claim holds on reading: both npm jobs need the gate to succeed and report auth=true, which a frozen auth package cannot do, and crates-armed reads the @cipherstash/auth FROZEN_PUBLISHERS entry; script tests covering this ran and passed in CI. Merging this PR therefore publishes nothing. The risk is latent and lands at PR E, when the entries are deleted: the new build differs from the repository's proven FFI native build in two ways that matter. The linux-x64-musl leg sets no `-C target-feature=-crt-static`, under which rustc drops the cdylib crate type, so the leg most likely fails and blocks every JS release on that push; and the gnu legs build on Ubuntu 24.04 runners with no glibc floor, where the FFI line pins glibc 2.28, so the published binaries may not load on older Linux distributions used by @cipherstash/stack consumers. Neither binary check is on the publish path; the preflight that checks architecture and libc is dispatch-only, cannot be run until merged, and does not test glibc version or musl loading.

### Failure scenarios

**FS-1 · linux-gnu auth binaries built on Ubuntu 24.04 with no glibc floor fail to load on older Linux** (high impact, plausible)

- Trigger: PR E arms the line; a version of @cipherstash/auth is published by publish-auth; a customer on a distribution with an older glibc (e.g. Debian 11, RHEL/Alma 8, Amazon Linux 2) installs @cipherstash/stack or @cipherstash/auth.
- Mechanism: _build-auth-artifacts.yml builds linux-x64-gnu on ubuntu-latest and linux-arm64-gnu on ubuntu-24.04-arm with plain `napi build --target <triple>` (lines 45-53, 112-116), so symbol versions are taken from the runner's glibc. The repository's FFI native line deliberately builds gnu targets through cargo-zigbuild with `--target <triple>.2.28` to pin the glibc floor (_build-ffi-artifacts.yml:240-244, ffi-release-matrix.mjs:59-60). The auth preflight only checks that libc.so.6 is NEEDED and smoke-loads on ubuntu-latest, which has the same glibc as the build host, so a raised floor passes every check.
- Consequence: require('@cipherstash/auth') throws `GLIBC_2.xx not found` at load time for those customers, breaking @cipherstash/stack (and cli, wizard) at runtime. npm publishes are irreversible; recovery is a new release built with a floor. Whether earlier versions published from cipherstash-suite supported these distributions is unknown.
- Affects: .github/workflows/_build-auth-artifacts.yml, @cipherstash/auth and six @cipherstash/auth-* platform packages (npm), @cipherstash/stack, cli, wizard (in-repo dependents of @cipherstash/auth), Customers' Node runtimes on Linux (glibc older than the build host, Alpine/musl)
- Evidence: `.github/workflows/_build-auth-artifacts.yml:37-116`; `.github/workflows/_build-ffi-artifacts.yml:240-244`; `scripts/ffi-release-matrix.mjs:59-60`; `.github/workflows/auth-preflight.yml:13-132`; `languages/typescript/packages/stack/package.json:230-233`
- Existing verification: auth-preflight.yml checks the gnu binaries link libc.so.6 and smoke-loads linux-x64-gnu on ubuntu-latest; dispatch-only and not run for this change. [exists_not_run]
- Missing verification: A check of the maximum GLIBC_* symbol version required by each gnu binary (e.g. objdump -T) against a stated floor.; A smoke load in an old-glibc container.
- Mitigation: Build the gnu legs with a pinned glibc floor as the FFI line does (cargo-zigbuild `<triple>.2.28`, or a manylinux-style container), and add a max-GLIBC-version assertion to the build or preflight; confirm the floor matches what cipherstash-suite previously shipped.

**FS-2 · linux-x64-musl leg built without -crt-static: cdylib dropped, auth build fails and blocks the JS release** (medium impact, plausible)

- Trigger: First armed run of auth-artifacts (or the first preflight dispatch) after merge.
- Mechanism: The musl leg installs musl-tools and runs `napi build --target x86_64-unknown-linux-musl` with no RUSTFLAGS (_build-auth-artifacts.yml:54-56, 68-73, 112-116); neither cargo config sets crt-static for musl (root .cargo/config.toml covers wasm only; the auth one covers macOS only). Rust's musl targets default to crt-static, under which rustc drops the cdylib crate type, so no .node is produced (this rustc behaviour is from general knowledge, not run here). The FFI line sets `RUSTFLAGS=-C target-feature=-crt-static` for exactly this target (_build-ffi-artifacts.yml:236-238). The `mv` of stack-auth-node.linux-x64-musl.node then fails, auth-artifacts fails, publish-auth is skipped, and `release` requires publish-auth success when auth=true (release.yml:471-482).
- Consequence: Fails closed: nothing auth is published, but the changeset publish for every other JS package on that push is also skipped until the workflow is fixed and re-run. If instead a statically linked musl module were produced, it would pass the preflight's musl check (which only asserts no glibc NEEDED) while possibly failing to load on Alpine; that variant would be high impact.
- Affects: .github/workflows/release.yml (Release JS), .github/workflows/_build-auth-artifacts.yml, @cipherstash/auth and six @cipherstash/auth-* platform packages (npm)
- Evidence: `.github/workflows/_build-auth-artifacts.yml:37-116`; `.github/workflows/_build-ffi-artifacts.yml:236-238`; `languages/typescript/packages/auth/.cargo/config.toml:10-11`; `.github/workflows/release.yml:457-482`; `.github/workflows/auth-preflight.yml:13-132`
- Existing verification: auth-build-artifacts.test.mjs checks the napi flags and matrix only; it does not check musl RUSTFLAGS. Ran in CI via test:scripts. [ran_passed]; auth-preflight.yml would build the musl leg; dispatch-only, not run. [exists_not_run]
- Missing verification: A run of _build-auth-artifacts.yml (via auth-preflight) before PR E arms the line.; A load test of the musl binary in an Alpine container.
- Mitigation: Set RUSTFLAGS='-C target-feature=-crt-static' on the musl leg (as _build-ffi-artifacts.yml does), and dispatch auth-preflight against main before PR E; consider adding an Alpine smoke load.

**FS-3 · Publish path ships platform binaries without the architecture/libc/load checks the preflight performs** (high impact, speculative)

- Trigger: Any mis-built platform binary (wrong arch on a cross-compiled leg such as darwin-x64 on arm64 macos-latest, wrong libc, a module missing exports) once the line is armed, with no preflight dispatched for that version.
- Mechanism: _build-auth-artifacts.yml verifies only the tarball name and that the expected .node filename exists (lines 145-164); publish-auth publishes what it downloads (release.yml:362-418). The architecture, readelf and smoke checks exist only in auth-preflight.yml, which is manual and not a `needs` of publish-auth.
- Consequence: A broken platform package is published irreversibly and breaks @cipherstash/auth (and @cipherstash/stack) on that platform until a new release.
- Affects: .github/workflows/release.yml (Release JS), .github/workflows/_build-auth-artifacts.yml, @cipherstash/auth and six @cipherstash/auth-* platform packages (npm), @cipherstash/stack, cli, wizard (in-repo dependents of @cipherstash/auth)
- Evidence: `.github/workflows/_build-auth-artifacts.yml:145-164`; `.github/workflows/release.yml:350-418`; `.github/workflows/auth-preflight.yml:13-132`
- Existing verification: Name and file-presence checks in the build; peer-version check of the wrapper. [exists_not_run]
- Missing verification: An architecture/libc check inside the reusable build (so it runs on the publish path), not only in the dispatch-only preflight.
- Mitigation: Move the `file`/readelf checks from auth-preflight.yml into _build-auth-artifacts.yml, and make running auth-preflight on the Version Packages branch a documented precondition of the first armed release.

### Recommended controls

- Pin a glibc floor for linux-x64-gnu and linux-arm64-gnu (zigbuild `.2.28` as the FFI line does, or an old-glibc container) and assert the maximum GLIBC_* version in the build. (compatibility_check; FS-1, VG-2)
- Add `RUSTFLAGS=-C target-feature=-crt-static` to the musl leg and extend auth-build-artifacts.test.mjs to require it, mirroring the FFI line. (test; FS-2)
- After merge and before PR E, dispatch auth-preflight.yml against main and keep its output as the evidence for arming; add Alpine and old-glibc smoke loads. (staged_rollout; FS-1, FS-2, FS-3, VG-1)
- Move the architecture and libc checks from auth-preflight.yml into _build-auth-artifacts.yml so they gate publish-auth. (review_focus; FS-3)
- Record what glibc and Node versions the cipherstash-suite-built auth binaries supported, so the new pipeline is checked against the same contract. (documentation; FS-1)

### What this assessment could not see

- How cipherstash-suite built and published @cipherstash/auth (glibc floor, musl flags, runners) is not available. Cannot say whether FS-1 is a regression for existing consumers or matches prior behaviour.
- No workflow or build was run locally (no network, no Rust cross toolchains); the rustc musl crt-static behaviour in FS-2 and glibc symbol versioning in FS-1 are from general toolchain knowledge. FS-1 and FS-2 stay plausible_failure rather than observed_defect.
- PR E (the arming change), crates.io/npm trusted-publisher configuration and the GPG secret are outside this diff. The crates line's first publish and the repointing were not assessed; a mis-configured publisher would fail loudly at PR E.
- CODEOWNERS and the dependency graph were not inputs; consumers were found by grepping package.json files. Omitted co-change signals (SECURITY.md, the EQL plan doc) were not followed up. External consumers of the auth packages are hypothetical; documentation drift was not assessed.
- Read closely: release-gate.mjs, eql-pipeline-armed.mjs, release.yml and release-plz.yml diffs, _build-auth-artifacts.yml, auth-preflight.yml, release-plz.toml, auth manifests. Skimmed: most new tests, cliff.toml, lint target-list edits, docs. A defect in cliff.toml changelog config or in test assertions could be missed; both are low impact for an inert change.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
