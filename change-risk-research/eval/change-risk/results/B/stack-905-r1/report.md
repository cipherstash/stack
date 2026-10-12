## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `c82c59d206..415ab2d43b`

Bumps the four exact-pinned CipherStash crates in protect-ffi (cipherstash-client, cts-common, stack-auth, stack-profile) from 0.42.0 to 0.42.2. The lockfile shows this also moves cipherstash-core/-config to 0.42.2, zerokms-protocol 0.12.26 -> 0.12.28, and jsonwebtoken 9.3.1 -> 10.4.0, swapping jsonwebtoken's crypto backend from ring to aws-lc-rs (already in the native graph via rustls, so native toolchain risk is low). No first-party code changes. The risk sits in upstream code that could not be read: a major-version JWT library change on the auth path that every ZeroKMS call depends on, a jsonwebtoken backend that may not compile for the shipped wasm32 entry, and opaque patch changes in the encryption/protocol crates. The Rust crates now differ from the @cipherstash/auth 0.42.0 npm catalog, which repo docs say should move together. The changeset is parked as .md.deferred, so the CVE fix does not reach published protect-ffi until the publishing cutover. Failures here would mostly be loud (build or auth errors), and the existing tests-rust and live integration-protect-ffi workflows are path-triggered by Cargo.lock, but no CI result was available.

### Failure scenarios

**FS-1 · jsonwebtoken 10 changes token handling in stack-auth, so ZeroKMS auth fails or tokens are mis-treated** (high impact, plausible)

- Trigger: Any encrypt/decrypt call that obtains a service token through AutoStrategy (access key, profile), a JS-backed @cipherstash/auth 0.42.0 strategy, or OIDC federation.
- Mechanism: stack-auth depends on jsonwebtoken, which moves a major version (9.3.1 -> 10.4.0) with stricter claim-type validation (the CVE fix) and a new crypto-provider model. protect-ffi turns every token into stack_auth::ServiceToken (lib.rs:815) and each ZeroKMS call goes through it. If stack-auth 0.42.2 decodes tokens or reads exp/nbf for refresh, a token that 9.x accepted, or a token minted by the 0.42.0 JS auth package, can be rejected or have its expiry misread. jsonwebtoken 10 may also fail at runtime if no crypto provider is selected on a target.
- Consequence: All encryption and decryption for affected consumers fails with auth errors after upgrade (an outage, loud). Or refresh mistimes and requests fail intermittently.
- Affects: protect-ffi native auth strategy path (NeonJsAuthStrategy / AutoStrategy -> stack_auth::ServiceToken), protect-ffi WASM entry (./wasm, ./wasm-inline) and @cipherstash/stack/wasm-inline, @cipherstash/stack, stack-drizzle, stack-supabase (workspace:* on protect-ffi)
- Evidence: `packages/protect-ffi/Cargo.lock:1907-1923`; `packages/protect-ffi/Cargo.lock:3383-3393`; `packages/protect-ffi/crates/protect-ffi/src/lib.rs:617-815`; `packages/protect-ffi/integration-tests/tests/oidc-federation.test.ts`
- Existing verification: integration-protect-ffi.yml runs live ZeroKMS suites, including js-strategy, oidc-federation and lock-context, native and WASM, and is triggered by Cargo.lock changes. [exists_not_run]
- Missing verification: A passing result from integration-protect-ffi on this head (credentialed run).; A review of the stack-auth 0.41->0.42.2 changes for how jsonwebtoken 10 is used (features, Validation settings).; Token refresh across expiry with the 0.42.0 JS auth package feeding the 0.42.2 Rust side.
- Mitigation: Require a green credentialed integration-protect-ffi run and the WASM Deno e2e before merging. Read the stack-auth 0.42.2 diff for its jsonwebtoken feature selection and Validation use.

**FS-2 · wasm32 build breaks because jsonwebtoken 10 now pulls in aws-lc-rs** (medium impact, plausible)

- Trigger: Building protect-ffi for wasm32-unknown-unknown (tests-rust clippy, wasm-pack in build-ffi-binding and _build-ffi-artifacts).
- Mechanism: stack-auth is an unconditional dependency (Cargo.toml:26), so it is in the wasm32 graph. The locked jsonwebtoken 10.4.0 lists aws-lc-rs and no longer lists ring. aws-lc-sys builds C with cmake and does not generally target wasm32-unknown-unknown. If stack-auth enables jsonwebtoken's aws_lc_rs backend without a target gate, the wasm build fails. The lockfile cannot show target gating.
- Consequence: The ./wasm and ./wasm-inline entries cannot be built. This blocks CI and the next protect-ffi release and leaves edge-runtime consumers unable to upgrade. It is loud, not silent.
- Affects: protect-ffi WASM entry (./wasm, ./wasm-inline) and @cipherstash/stack/wasm-inline, CI: tests-rust.yml (host + wasm32 clippy, cargo test) and integration-protect-ffi.yml (live ZeroKMS native + WASM), Published @cipherstash/protect-ffi + six platform packages (fixed changeset group)
- Evidence: `packages/protect-ffi/crates/protect-ffi/Cargo.toml:20-46`; `packages/protect-ffi/Cargo.lock:1907-1923`; `packages/protect-ffi/package.json:37-62`; `.github/workflows/tests-rust.yml:15-22`
- Existing verification: tests-rust.yml runs clippy for host and wasm32 on Cargo.lock changes. The Deno WASM e2e and integration WASM round trips build via wasm-pack. [exists_not_run]
- Missing verification: A seen result of the wasm32 clippy or wasm-pack build at this head.
- Mitigation: Confirm the tests-rust wasm32 step and a wasm-pack build pass before merge. If they fail, the upstream crate needs a wasm-gated jsonwebtoken backend (for example rust_crypto on wasm32).

**FS-3 · Opaque patch changes in cipherstash-client/core/config or zerokms-protocol alter ciphertext or protocol behaviour** (high impact, speculative)

- Trigger: Encrypting with the 0.42.2 crates and reading data written by 0.42.0 (or vice versa), or using search terms against installed EQL SQL.
- Mechanism: The change pulls in unreviewed upstream patch releases of the crates that produce encrypted payloads and talk to ZeroKMS (cipherstash-core, cipherstash-config, cipherstash-client 0.42.2, zerokms-protocol 0.12.28). The changeset asserts 'No API changes', but API stability does not establish payload or protocol stability, and none of the crate sources were visible.
- Consequence: If payload or search-term encoding shifted, values written at rest become undecryptable or unqueryable by older readers or SQL (silent, data-integrity).
- Affects: packages/protect-ffi Rust crate (Cargo.toml / Cargo.lock), @cipherstash/stack, stack-drizzle, stack-supabase (workspace:* on protect-ffi), Published @cipherstash/protect-ffi + six platform packages (fixed changeset group)
- Evidence: `packages/protect-ffi/Cargo.lock:4985-4990`; `.changeset/protect-ffi-jsonwebtoken-cve.md.deferred:1-5`
- Existing verification: Live round-trip suites (scalar, json, query, postgres, eql-v3) in integration-protect-ffi exercise encrypt->decrypt and query at one version. [exists_not_run]
- Missing verification: A cross-version check: decrypt and query payloads produced by 0.42.0 using 0.42.2.; The upstream changelog for cipherstash-client 0.42.1/0.42.2 and zerokms-protocol 0.12.27/0.12.28.
- Mitigation: Read the upstream release notes for these patches. If they touch payload or term generation, add a fixture-based cross-version decrypt/query test.

**FS-4 · Rust crates move to 0.42.2 while the @cipherstash/auth npm catalog stays at 0.42.0, leaving the CVE in the auth binding** (medium impact, plausible)

- Trigger: Shipping stack/CLI with @cipherstash/auth 0.42.0 next to protect-ffi built on stack-auth 0.42.2.
- Mechanism: dependabot.yml records the four crates as the same release train as the @cipherstash/auth catalog and says to bump them together 'in step with the npm catalog'. pnpm-workspace.yaml still pins @cipherstash/auth and its six bindings at 0.42.0, and the dependabot comment still says =0.42.0. JS-backed strategies hand tokens and failure codes across this version boundary (lib.rs:617-655).
- Consequence: The CLI and stack auth binding probably keeps jsonwebtoken 9.x, so the advertised CVE remediation is partial. A cross-version token or error-code mismatch would degrade to AuthError::Custom or to auth failures.
- Affects: protect-ffi native auth strategy path (NeonJsAuthStrategy / AutoStrategy -> stack_auth::ServiceToken), @cipherstash/auth 0.42.0 native bindings (CLI, stack)
- Evidence: `.github/dependabot.yml:128-145`; `pnpm-workspace.yaml:11-30`; `packages/protect-ffi/crates/protect-ffi/src/lib.rs:617-815`
- Existing verification: e2e/tests/supply-chain.e2e.test.ts enforces lockstep within the npm auth set only, not Rust<->npm. [exists_not_run]
- Missing verification: A check or decision record that the Rust crate train may run ahead of the npm @cipherstash/auth catalog.
- Mitigation: Bump the @cipherstash/auth catalog (all seven) to 0.42.2 in the same release, or record why the skew is acceptable. Update the stale =0.42.0 comment in dependabot.yml.

### Recommended controls

- Require a green credentialed integration-protect-ffi run (native + WASM, including js-strategy and oidc-federation) and the tests-rust wasm32 clippy step on this head before merge. (test; FS-1, FS-2, VG-1)
- Read the stack-auth 0.42.0->0.42.2 diff for jsonwebtoken 10 feature selection (aws_lc_rs vs rust_crypto, wasm gating) and Validation/decoding settings. Read the cipherstash-client and zerokms-protocol release notes for payload or term changes. (review_focus; FS-1, FS-2, FS-3, VG-2)
- Decrypt and query a fixture set encrypted with 0.42.0 using the 0.42.2 build. (compatibility_check; FS-3, VG-3)
- Bump the @cipherstash/auth catalog to 0.42.2 in lockstep, or record the accepted skew. Update the stale dependabot.yml comment. Track the deferred changeset so the CVE fix actually ships at cutover. (other; FS-4)

### What this assessment could not see

- Upstream crate sources and changelogs (crates.io) were not reachable. jsonwebtoken 10 behaviour comes from general knowledge of the release, not from reading its code. FS-1 to FS-3 rest on lockfile evidence and inference. Their likelihood cannot be judged.
- The Cargo lockfile does not record target-specific feature activation, so it cannot show whether aws-lc-rs enters the wasm32 graph. FS-2 stays plausible_failure, not an observed defect.
- No CI results and no local build (no network to fetch crates). Every verification is exists_not_run. Verification confidence is low.
- Not introduced by this change: published protect-ffi is still released from cipherstash/protectjs-ffi during the absorption (head commit message). The deferred changeset means the CVE fix does not reach customers through this repo yet. Customer exposure to FS-1 to FS-3 is deferred to the cutover release. The vulnerability also persists until then.

_Inputs unavailable: ci_results, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
