# WASM / Supabase Edge support for protect-ffi + cipherstash-client

## Goal

Run encrypt/decrypt against ZeroKMS from a Supabase Edge Function (Deno runtime, single-threaded, all outbound HTTP through `fetch`, ~10MB deployable budget).

## Layered plan

Originally scoped as four layers. After looking more carefully at cipherstash-client, the dominant blockers for what was Layer 2 (`tokio::spawn` background refresh, `std::fs` token caches, `dirs`/`open` interactive auth) all live inside legacy credentials code that is **already unused** in current cipherstash-client — kept alive only because proxy is pinned to a pre-migration version. Promoting that cleanup to its own layer ahead of the wasm-specific work shrinks the remaining work substantially.

Five layers, Layer 1 already shipped:

### Layer 1 — Pure crypto/protocol crates [DONE]

Six crates compile clean for `wasm32-unknown-unknown`: `recipher`, `cipherstash-core`, `cipherstash-config`, `cllw-ore` (`--no-default-features`), `cts-common` (`--no-default-features`), `zerokms-protocol`. See "Layer 1 — what shipped" below.

`vitaminc-encrypt` got a cfg-based dual backend (aws-lc-rs on native, RustCrypto on wasm32) so cipherstash-suite can use AEAD types from `vitaminc::encrypt` on both targets without a feature-gate workaround. Available from vitaminc 0.2.0-pre on crates.io (vitaminc PR #163, shipped as part of the 0.2.0-pre minor-bump release).

### Layer 2 — Legacy credentials cleanup [DONE]

Shipped in PR #1943. cipherstash-client 0.34 already migrated every consumer-facing type to the bound `for<'a> &'a C: AuthStrategy` from `stack-auth`; the whole legacy `Credentials` / `AutoRefreshable` tree was dead, kept alive only because proxy is pinned to `cipherstash-client = "0.32.2"`. Deleted modules: `credentials/{auto_refresh, user_credentials, service_credentials, static_credentials, token_store}`, the `Credentials`/`AutoRefreshable`/`TokenExpiry` traits, the never-imported `logger_client`/`reqwest_client` modules, and the `sleep` wrapper. -2042 lines. Dropped `open` and `cfg-if` deps.

`ServiceToken` (the legacy JSON-wire type at `cipherstash_client::credentials::service_credentials::service_token::ServiceToken`) is intentionally retained — it backs a `serde::Deserialize`able `{accessToken, expiry}` contract that protect-ffi consumes, and migrating it requires a separate design decision.

The cipherstash-client release + proxy bump (separate concern, not blocking wasm work) remains as a follow-up.

### Layer 3 — `stack-auth` + `cipherstash-client` wasm32 compile [DONE]

Shipped in PR #1944. Both crates now build for `wasm32-unknown-unknown`. The wasm-compatible auth surface is `AccessKeyStrategy` (full M2M flow with token caching), `OAuthStrategy::with_token` (caller-supplied JWT with in-memory refresh) — the path edge workers will use — and `ZeroKMS<S>::encrypt`/`decrypt` against any wasm-compatible strategy.

Deliberately not on wasm: `device_code` flow (uses `open::that`), `stack-profile` (filesystem), `cts_client`, `management`, `config::source`, `config::paths`, `config::docker_env_file`. Per-target dep splits in `stack-auth` and `cipherstash-client` work around workspace `tokio = { features = ["full"] }` (pulls `mio`, which doesn't compile to wasm32) by giving each affected crate a target-conditional minimal tokio.

### Layer 3.5 — `stack-auth-wasm` bindings crate [IN PROGRESS]

This PR. Adds `packages/stack-auth/wasm` as a sibling to the existing napi crate. Scoped to `AccessKeyStrategy` (M2M auth) — `getToken(): Promise<TokenResult>` returning `{ token, subject, workspaceId, issuer, services }`. Errors carry a `.code` enum matching the napi contract. OAuth-based strategies (`OAuthStrategy`, `AutoStrategy`, device-code) are deferred to a follow-up: federation and token-pinning for browser/edge contexts need design work that hasn't happened yet.

Error-code mapping is hoisted onto `AuthError::error_code()` in the parent `stack-auth` crate so this PR and the existing napi sibling can share one source of truth (napi adoption is a non-functional cleanup for a follow-up).

Build targets: `wasm-pack build --target bundler` (primary — Supabase Edge, Vite, Webpack) and `--target deno` (vanilla `deno run` only — Supabase Edge Runtime sandbox blocks `fetch('file://…')` so the deno target's auto-fetch of its `.wasm` sibling fails there; the bundler output uses `import * as wasm from "./*.wasm"` which the Edge Runtime resolves natively). Tests run via `wasm-pack test --node` — pure-logic coverage (JWT claim extraction, error-code mapping, constructor smoke). HTTP semantics stay covered by the existing native `stack-auth/node/__tests__` vitest suite. CI gains the wasm32 cargo-check + wasm-pack test step alongside the existing nextest step in `test-stack-auth.yml`.

Rationale for this intermediate layer: protect-wasm (Layer 4) will need to wrap auth strategies anyway. Establishing the wasm-bindgen toolchain and error-enrichment pattern here on a tiny crate (~205 LOC, 6 tests) means Layer 4 doesn't absorb both the toolchain bootstrap and the encrypt/decrypt porting work in the same PR.

End-to-end validated against a live Supabase Edge Function returning a real `TokenResult` from `AccessKeyStrategy.getToken()` against `ap-southeast-2.aws`. The validation surfaced three runtime issues fixed in this PR:

- `stack-auth` called `std::time::SystemTime::now()` in `token.rs` and `access_key_refresher.rs` for JWT-expiry checks. The stdlib's `wasm32-unknown-unknown` `time` module is a panicking stub. Swapped to `web_time::{SystemTime, UNIX_EPOCH}` (re-exports `std::time` on native, polyfills via JS time APIs on wasm — no behavior change off wasm).
- Rust panics on wasm surface as opaque `RuntimeError: unreachable` from bytecode offsets. Added `console_error_panic_hook` and route panics to `console.error` via a `#[wasm_bindgen(start)]` module-init function.
- `wasm-pack --target deno` doesn't work in the Supabase Edge Runtime — its sandbox blocks `fetch('file://…')`, which is how the deno target loads its sibling `.wasm`. Made `--target bundler` the primary build (uses `import * as wasm from "./*.wasm"`, which Edge resolves natively); deno target retained for vanilla `deno run`.

### Layer 4 — `protect-wasm` bindings

`protect-ffi` is napi-only. Add a sibling crate `protect-wasm` in the protect-ffi repo using `wasm-bindgen` + `wasm-bindgen-futures` + `serde-wasm-bindgen`. Port the 12 `#[neon::export]` functions in `protect-ffi/crates/protect-ffi/src/lib.rs:728-1148`. Build with `wasm-pack` (target deno or web depending on the packaging story).

### Layer 5 — Validation in a Supabase Edge Function

Deploy a real edge function that calls `protect-wasm`, encrypt/decrypt against ZeroKMS, measure:

- Bundle size vs the 10MB cap
- Cold-start latency
- Round-trip correctness against a server-side native client
- Cross-backend ciphertext compatibility — encrypt on wasm (RustCrypto), decrypt on native (aws-lc-rs), and vice versa. This is the cross-backend compat test deferred from earlier.

## Supabase Edge runtime specifics

- Deno-based, supports `WebAssembly.instantiate`
- Single-threaded — no `tokio::spawn` across threads, no `rayon`
- Outbound HTTP only via host `fetch` (reqwest's wasm backend uses this transparently)
- No filesystem, no env beyond what the function declares
- Bundle size cap ~10MB. Crypto + reqwest + serde stack will land ~1.5–3MB stripped
- Cold start: each invocation may be a fresh instance — token caching is in-memory and short-lived

## Status

- [x] Analysis (this doc)
- [x] Layer 1 — pure crates verified on wasm32 (PR #1942)
- [x] Layer 2 — legacy credentials cleanup (PR #1943)
- [x] Layer 3 — `stack-auth` + `cipherstash-client` compile on wasm32 (PR #1944)
- [ ] Layer 3.5 — `stack-auth-wasm` bindings crate (this PR)
- [ ] Layer 4 — `protect-wasm` bindings (in protect-ffi repo)
- [ ] Layer 5 — Supabase Edge validation

## Layer 1 — what shipped

Verified on `cargo check --target wasm32-unknown-unknown`:

| Crate | Invocation |
|---|---|
| `recipher` | `cargo check --target wasm32-unknown-unknown -p recipher` |
| `cipherstash-core` | `cargo check --target wasm32-unknown-unknown -p cipherstash-core` |
| `cipherstash-config` | `cargo check --target wasm32-unknown-unknown -p cipherstash-config` |
| `cllw-ore` | `cargo check --target wasm32-unknown-unknown -p cllw-ore --no-default-features` (postgres-types is server-only) |
| `cts-common` | `cargo check --target wasm32-unknown-unknown -p cts-common --no-default-features` |
| `zerokms-protocol` | `cargo check --target wasm32-unknown-unknown -p zerokms-protocol` |

Changes:

- `.cargo/config.toml` — wasm32 rustflag `--cfg getrandom_backend="wasm_js"` (required by `getrandom >= 0.3` to select the browser/Deno backend; pulled in via `vitaminc-random` → `rand 0.10`)
- Per-crate wasm32 target deps for `getrandom` (`js` feature for v0.2, `wasm_js` for v0.4) so feature unification activates the right backend
- `cts-common` wasm32 target dep on `uuid = { features = ["js"] }` so `Uuid::new_v4()` can source entropy
- Workspace `vitaminc`, `vitaminc-aead`, and `vitaminc-protected` pinned to `0.2.0-pre` on crates.io — the first release containing the cfg-based dual backend (aws-lc-rs on native, RustCrypto on wasm32) for `vitaminc-encrypt`. Shipped via [vitaminc PR #163](https://github.com/cipherstash/vitaminc/pull/163).

Native build verified via `mise run lint`. `cts-common` unit tests: 138/138 passing.

## Layer 2a — what shipped

Deleted from cipherstash-client (PR #1943):

- `credentials/auto_refresh.rs`
- `credentials/user_credentials/` (auth0, okta, user_token, mod)
- `credentials/service_credentials/{service_user_credentials, service_access_key_credentials}.rs`
- `credentials/static_credentials.rs`, `credentials/token_store.rs`
- `credentials::{Credentials, AutoRefreshable, TokenExpiry}` traits and associated error types
- `logger_client.rs`, `reqwest_client.rs`, `sleep.rs`

Cargo.toml: dropped `open` and `cfg-if` deps. Kept `tokio` feature flag (still used by `encryption/builder/mod.rs` and `eql`).

Net delta: 19 files changed, +14 / -2042. Verified via `cargo check --workspace --tests` (no `--all-features`, to avoid the lint-trap class), `mise run lint`, and 340 cipherstash-client unit tests passing.

`cipherstash_client::credentials::ServiceToken` is the only piece of the credentials tree that survives, retained for its JSON wire contract with protect-ffi.

## Known follow-ups

- Layer 1's `cargo check` verification is now partially exercised by Layer 3.5's `wasm-pack build` (pulls `cts-common`, `cipherstash-config`, `zerokms-protocol` transitively). Crates outside that dep graph (`recipher`, `cipherstash-core`, `cllw-ore`) still need a real artifact build.
- `cllw-ore` requires `--no-default-features` because the default `postgres-types` feature has C deps. Consider flipping the default off in a future major version (already noted in its Cargo.toml).
- Cipherstash-client 0.35 release containing the legacy delete; proxy bump to 0.35 with `AccessKeyStrategy` migration. See Layer 2c.
- `ServiceToken` JSON contract migration (Layer 2b) — design conversation needed before code.
- Pre-existing API drift between cipherstash-client and protect-ffi (path dep) — `cipherstash_client::eql::EncryptedField` not found. Surfaces under `cargo check -p protect-ffi`. Not caused by Layer 2a; flagged for the next protect-ffi sync.
- Adopt `AuthError::error_code()` in `stack-auth-node` (the napi sibling) — currently inlined there, now duplicates the parent crate.
- OAuth-based wasm strategies (`OAuthStrategy`, `AutoStrategy`, device-code) — deferred from Layer 3.5 pending federation/token-pinning design.
- Token cookie pinning — encrypt the JWT under a worker-only key before storing in cookies (so a stolen cookie can't be replayed elsewhere).
- Never-expose-JWT API — wallet/keychain pattern where the JWT lives only in wasm memory and JS calls signed operations.
- npm publishing strategy — separate `@cipherstash/stack-auth-wasm` package vs sub-path under existing `@cipherstash/auth` vs conditional exports.
