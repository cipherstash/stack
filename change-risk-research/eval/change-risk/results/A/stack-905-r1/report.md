## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `c82c59d206..415ab2d43b`

Dependency-only change to the protect-ffi native/WASM binding: the four exact-pinned CipherStash crates (cipherstash-client, cts-common, stack-auth, stack-profile) move from =0.42.0 to =0.42.2, which pulls zerokms-protocol 0.12.26 -> 0.12.28 and, via stack-auth, jsonwebtoken 9.3.1 -> 10.4.0 (CVE-2026-25537 fix). No protect-ffi Rust or TypeScript source changes. The material risk is a major-version swap of the JWT library underneath the authentication path every encrypt/decrypt depends on: jsonwebtoken 10 switches its crypto backend from ring to aws-lc-rs and tightens claim validation, and stack-auth is compiled into both the native and the wasm32 builds. Upstream sources could not be read offline, so whether token handling is behaviour-identical is unknown. CI exists that would catch both failure modes (tests-rust.yml clippy on host+wasm32; integration-protect-ffi.yml live ZeroKMS round-trips for native and WASM, both path-triggered by Cargo.lock), but no results were supplied. The changeset is parked as .md.deferred per the documented publishing-cutover process, so this fix does not reach npm consumers until the cutover PR renames it. Minor: dependabot.yml still documents the crates as =0.42.0 'in step with' the npm @cipherstash/auth catalog, which stays at 0.42.0.

### Failure scenarios

**FS-1 · jsonwebtoken 10 inside stack-auth rejects or mishandles service-issued tokens, breaking auth for every encrypt/decrypt** (high impact, plausible)

- Trigger: stack-auth 0.42.2 decodes or validates a CTS/ZeroKMS access token whose claims or algorithm were accepted by jsonwebtoken 9.3.1 but are handled differently by 10.4.0 (stricter claim-type validation, changed decode/validation defaults, or a crypto-provider selection that differs at runtime).
- Mechanism: stack-auth depends on jsonwebtoken (Cargo.lock head 3384-3408), which jumps a major version with a new crypto backend (aws-lc-rs instead of ring) and the CVE-2026-25537 validation fix (Cargo.lock head 1908-1923 vs base 1908-1920). protect-ffi itself has no source change, so any behavioural difference in token handling flows straight into the auth strategy every client builds (client_options.rs build_strategy).
- Consequence: Published native and WASM bindings fail to obtain or refresh credentials, so every encryption and decryption call returns an auth failure for all users of the new binding. Loud, not silent, but publishing is irreversible and needs a new release to fix.
- Affects: @cipherstash/protect-ffi native binding (index.node, six @cipherstash/protect-ffi-<platform> packages), @cipherstash/protect-ffi WASM build (dist/wasm, ./wasm-inline) and @cipherstash/stack/wasm-inline, @cipherstash/stack and other JS consumers of protect-ffi
- Evidence: `packages/protect-ffi/Cargo.lock:1908-1923`; `packages/protect-ffi/Cargo.lock:3384-3408`; `packages/protect-ffi/crates/protect-ffi/src/client_options.rs:128-135`; signal `ci.available`
- Existing verification: integration-protect-ffi.yml runs the live encrypt/decrypt/lock-context suite against real ZeroKMS for native and WASM on PRs touching Cargo.lock; this exercises token acquisition end to end. [exists_not_run]
- Missing verification: Result of integration-protect-ffi.yml on this PR (requires CipherStash secrets; would not run on a fork PR).; A token-refresh / expiry path test: the live suite likely completes within one token lifetime, so exp/nbf handling after refresh is probably not exercised.; Upstream stack-auth 0.42.0..0.42.2 changelog or diff confirming no behavioural change beyond the dependency bump.
- Mitigation: Require a green credentialed integration-protect-ffi run (native and WASM) before merging; read the stack-auth 0.42.2 release notes; publish through the deferred changeset only after a smoke test of a long-running client across a token refresh.

**FS-2 · jsonwebtoken 10's aws-lc-rs backend breaks the wasm32 build or panics at first token use on wasm** (high impact, plausible)

- Trigger: The wasm32-unknown-unknown build (wasm-pack / clippy) resolves jsonwebtoken 10 with the aws_lc_rs backend, or with no backend enabled on that target.
- Mechanism: jsonwebtoken 9 used ring, which builds for wasm32; 10.4.0 now lists aws-lc-rs (Cargo.lock head 1908-1923). stack-auth is an unconditional dependency compiled for wasm32 (Cargo.toml head 20-26, 48-56; client_options.rs 128-135). aws-lc-rs was already in the tree at base via rustls/quinn (base Cargo.lock 2973-2978), but those are network-stack crates that may not be compiled for wasm32, so the backend is new to the wasm graph. If no usable backend is enabled on wasm, jsonwebtoken 10 compiles but fails at runtime when it first needs a crypto provider.
- Consequence: Either the WASM build fails (loud; blocks the wasm-inline entry and release build), or the shipped WASM binding compiles but cannot authenticate at runtime on edge runtimes.
- Affects: @cipherstash/protect-ffi WASM build (dist/wasm, ./wasm-inline) and @cipherstash/stack/wasm-inline, CI: tests-rust.yml and integration-protect-ffi.yml
- Evidence: `packages/protect-ffi/Cargo.lock:1908-1923`; `packages/protect-ffi/Cargo.lock:1908-1920` (base); `packages/protect-ffi/crates/protect-ffi/Cargo.toml:20-56`; `packages/protect-ffi/crates/protect-ffi/src/client_options.rs:128-135`
- Existing verification: tests-rust.yml runs clippy against wasm32-unknown-unknown on PRs touching Cargo.lock (catches a compile failure only). [exists_not_run]; integration-protect-ffi.yml builds dist/wasm with wasm-pack and runs the WASM round-trip against live ZeroKMS (would catch a runtime backend panic). [exists_not_run]
- Missing verification: CI results for the wasm32 clippy job and the WASM round-trip test on this PR.; Confirmation of which jsonwebtoken features stack-auth 0.42.2 enables on wasm32 (e.g. `cargo tree -e features --target wasm32-unknown-unknown -i jsonwebtoken`).
- Mitigation: Run `cargo tree --target wasm32-unknown-unknown -e features -i jsonwebtoken` and `mise run lint:rust` locally or confirm CI; confirm the WASM round-trip test passed before publishing.

**FS-3 · Rust crates move to 0.42.2 while the documented-lockstep npm @cipherstash/auth catalog stays at 0.42.0** (low impact, observed in the code)

- Trigger: A maintainer follows dependabot.yml guidance, or a later bump assumes crates and catalog share a version.
- Mechanism: dependabot.yml (head 127-135) says the four crates 'all sit at =0.42.0, matching the catalog's 0.42.0' and should be bumped 'in step with the npm catalog'; this change bumps only the crates and leaves both the comment and pnpm-workspace.yaml (line 24, @cipherstash/auth 0.42.0) unchanged.
- Consequence: Stale guidance and a version skew between the JS auth package and the Rust auth crate. No runtime coupling between the two binaries was found, so the effect is mainly misleading maintenance guidance; any CVE exposure in @cipherstash/auth's own jsonwebtoken is outside this change.
- Affects: .github/dependabot.yml lockstep guidance and the @cipherstash/auth npm catalog
- Evidence: `.github/dependabot.yml:127-135`; `pnpm-workspace.yaml:24`
- Missing verification: Check whether @cipherstash/auth 0.42.0 bundles the vulnerable jsonwebtoken and needs the matching 0.42.2 catalog bump.
- Mitigation: Update the dependabot.yml comment to =0.42.2, and either bump the @cipherstash/auth catalog entries together or record why the two release trains diverge.

### Recommended controls

- Confirm green runs of tests-rust.yml (including the wasm32 clippy arm) and a credentialed integration-protect-ffi.yml run (native + WASM round-trip) on this head before merge. (test; FS-1, FS-2, VG-1)
- Run `cargo tree -e features -i jsonwebtoken` for the host and for wasm32-unknown-unknown to confirm which backend is enabled per target; read the stack-auth 0.42.2 release notes for behavioural changes. (compatibility_check; FS-2, VG-3)
- Because the changeset is deferred, publish happens at the cutover. Before that publish, smoke-test a long-lived client across a token refresh on one native platform and on the WASM entry. (staged_rollout; FS-1, VG-2)
- Update the dependabot.yml crate-pin comment to 0.42.2 and decide whether the @cipherstash/auth catalog moves with it. (documentation; FS-3)
- Track the deferred changeset so the CVE fix actually ships at the publishing cutover; until then published @cipherstash/protect-ffi binaries keep jsonwebtoken 9.3.1. (review_focus; FS-1)

### What this assessment could not see

- Upstream crate sources and changelogs (stack-auth, cipherstash-client, cts-common, stack-profile 0.42.0 -> 0.42.2; zerokms-protocol 0.12.26 -> 0.12.28; jsonwebtoken 10) were not available offline. The behaviour of the upgraded auth path, and any non-jsonwebtoken change in these patch releases, is unknown; FS-1 and FS-2 stay plausible_failure rather than confirmed or ruled out.
- No CI results and no build or test run by the assessor (cargo would need the registry cache outside the working directory or network). All verification is exists_not_run; verification confidence is capped at medium.
- No PR description; intent was taken from the PR title, the deferred changeset text and the commit messages. Any testing the author reports doing is not reflected.
- Cargo.lock records the feature-unified dependency set across all targets, so it cannot show which jsonwebtoken backend is enabled for wasm32 specifically. FS-2's trigger cannot be confirmed or excluded from the inputs.

_Inputs unavailable: pr_description, ci_results, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
