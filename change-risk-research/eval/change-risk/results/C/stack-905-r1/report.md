## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `c82c59d206..415ab2d43b`

Lockfile/manifest-only change to the Rust half of @cipherstash/protect-ffi: pins cipherstash-client, cts-common, stack-auth and stack-profile move =0.42.0 -> =0.42.2, which also moves cipherstash-config, cipherstash-core and zerokms-protocol (0.12.26 -> 0.12.28), and moves stack-auth's jsonwebtoken from 9.3.1 (ring backend) to 10.4.0 (aws-lc-rs backend) to address CVE-2026-25537. No first-party source changes. The material risk is a behaviour change inside the token-handling and encryption crates that this repository cannot see: a stricter JWT major version could reject or mis-handle service tokens and break every encrypt/decrypt call. CI on the head commit is fully green, including the live protect-ffi integration suite, Rust test+clippy (host and wasm32) and the Deno WASM E2E, which covers the happy path. aws-lc-rs was already in the build graph at base (rustls, vitaminc-encrypt), so new native build toolchain risk is small. The changeset is parked as .md.deferred per the documented pre-cutover convention, so nothing publishes from this PR and the CVE fix does not reach npm consumers until the cutover PR.

### Failure scenarios

**FS-1 · jsonwebtoken 10 handles service-token claims differently, so auth fails or token refresh breaks** (high impact, plausible)

- Trigger: stack-auth (via AutoStrategy or a JS-backed strategy) decodes or validates a CTS/OIDC-federated service token whose claims jsonwebtoken 10 treats differently from 9.3.1 (e.g. stricter nbf/exp typing, required-claim defaults, or missing crypto-provider selection on some target), especially at refresh time after the first token expires.
- Mechanism: jsonwebtoken moves across a major version with a new crypto backend (Cargo.lock jsonwebtoken entry at head). stack-auth is its only dependent. protect-ffi obtains every ServiceToken through stack-auth (lib.rs, wasm.rs, client_options.rs). The upstream stack-auth diff 0.42.0 -> 0.42.2 that adapts to the new API could not be read.
- Consequence: Clients fail to obtain or refresh a token, so encrypt/decrypt fails for all users on the affected path (fails loudly, no data corruption). A refresh-only failure would show up only in long-running processes, after the first token expires.
- Affects: protect-ffi auth strategy integration (AutoStrategy / JS-backed AuthStrategy -> ServiceToken), @cipherstash/protect-ffi native platform binaries and WASM build, @cipherstash/stack and adapters (stack-drizzle, stack-supabase, prisma-next) consuming protect-ffi
- Evidence: `packages/protect-ffi/Cargo.lock:1908-1923`; `packages/protect-ffi/crates/protect-ffi/src/lib.rs:60`; `packages/protect-ffi/crates/protect-ffi/src/client_options.rs:135-136`; `packages/protect-ffi/integration-tests/tests/oidc-federation.test.ts:26-39`; ci_result
- Existing verification: protect-ffi integration suite (live encrypt/decrypt, lock context, JS auth strategies, WASM round trip) on head commit [ran_passed]; cargo test + clippy + rustfmt (host and wasm32 clippy) on head commit [ran_passed]; Run WASM E2E Tests (Deno), which fails rather than skips when CS_* credentials are missing [ran_passed]; PR author reports cargo test --lib 310 passed locally [unknown]
- Missing verification: A run long enough, or with a short-lived token, to exercise token refresh/expiry handling under jsonwebtoken 10.; OIDC federation end-to-end with a real third-party JWT (oidc-federation.test.ts explicitly covers only the constructor contract).; Review of the upstream stack-auth 0.42.0 -> 0.42.2 diff for how jsonwebtoken 10 features/validation are configured.
- Mitigation: Read the stack-auth 0.42.2 changelog/diff for its jsonwebtoken Validation settings and feature selection; run one integration test with a forced token refresh before the cutover release; keep the previous protect-ffi version available for consumer pin-back.

**FS-2 · Release-time platform build of the new graph fails or misbehaves on a target PR CI does not build** (medium impact, plausible)

- Trigger: The cutover release runs _build-ffi-artifacts.yml for the six platforms (darwin-x64, darwin-arm64, win32-x64-msvc, linux-x64-gnu, linux-arm64-gnu cross, linux-x64-musl) with jsonwebtoken now linking aws-lc-rs.
- Mechanism: PR CI builds only the host and wasm32; the six-platform matrix runs only from release.yml or the manually dispatched ffi-preflight.yml. aws-lc-rs was already compiled at base via rustls/vitaminc-encrypt, so the new edges are jsonwebtoken -> aws-lc-rs and pure-Rust crates, which lowers the likelihood.
- Consequence: The release job fails closed and needs a fix and re-run; or, if one platform build silently differs, a broken binary ships for that platform.
- Affects: @cipherstash/protect-ffi native platform binaries and WASM build
- Evidence: `python3 deps.py (tomllib parse of base and head Cargo.lock; lists dependents of aws-lc-rs, ring, jsonwebtoken)`; `.github/workflows/tests.yml:357-358`; `.github/workflows/_build-ffi-artifacts.yml:20-22`
- Existing verification: Host cargo build/test and wasm32 clippy in CI [ran_passed]
- Missing verification: ffi-preflight.yml dispatch against this revision (or the Version Packages branch) covering all six targets.
- Mitigation: Dispatch ffi-preflight.yml before the cutover, as AGENTS.md already prescribes.

### Recommended controls

- Review the upstream stack-auth 0.42.0 -> 0.42.2 diff, especially jsonwebtoken Validation and feature configuration and any claim-parsing change, and the cipherstash-client/zerokms-protocol release notes, for payload- or wire-affecting changes. (review_focus; FS-1, VG-2)
- Run one integration test that forces a token refresh (short-lived token or clock skew) under the new graph. (test; FS-1, VG-1)
- Decrypt a sample of ciphertexts produced by protect-ffi built on 0.42.0 with the 0.42.2 build before the cutover release. (compatibility_check; VG-2)
- Dispatch ffi-preflight.yml for all six platforms before the cutover release. (test; FS-2, VG-3)
- Update AGENTS.md / the absorption plan, which still say two changesets are parked; there are now three, and the CVE fix ships only when the cutover renames them. (documentation; VG-3)

### What this assessment could not see

- Upstream crate sources and changelogs (stack-auth, cipherstash-client, cipherstash-core, cipherstash-config, zerokms-protocol, jsonwebtoken 10) were unavailable offline. Cannot confirm 'No API changes' or rule out payload or wire changes in the encryption crates; FS-1 is plausible_failure rather than confirmed or ruled out.
- ci.json gives job conclusions only, without logs. Cannot confirm that credentialed suites ran their live tests rather than skipping, beyond the workflow comment that the WASM E2E fails when credentials are missing.
- Whether the CVE is reachable in protect-ffi's client-side use of stack-auth (it receives tokens rather than validating third-party tokens for access control) was not established. The security benefit of the bump is unquantified; this does not change the release risk.
- CODEOWNERS and deployment context were not available inputs. Reviewer routing and rollout controls are not assessed.

_Inputs unavailable: codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
