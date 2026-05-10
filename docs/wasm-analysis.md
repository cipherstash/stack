# WASM / Supabase Edge support for protect-ffi + cipherstash-client

## Goal

Run encrypt/decrypt against ZeroKMS from a Supabase Edge Function (Deno runtime, single-threaded, all outbound HTTP through `fetch`, ~10MB deployable budget).

## Layered plan

Originally scoped as four layers. After looking more carefully at cipherstash-client, the dominant blockers for what was Layer 2 (`tokio::spawn` background refresh, `std::fs` token caches, `dirs`/`open` interactive auth) all live inside legacy credentials code that is **already unused** in current cipherstash-client — kept alive only because proxy is pinned to a pre-migration version. Promoting that cleanup to its own layer ahead of the wasm-specific work shrinks the remaining work substantially.

Five layers, Layer 1 already shipped:

### Layer 1 — Pure crypto/protocol crates [DONE]

Six crates compile clean for `wasm32-unknown-unknown`: `recipher`, `cipherstash-core`, `cipherstash-config`, `cllw-ore` (`--no-default-features`), `cts-common` (`--no-default-features`), `zerokms-protocol`. See "Layer 1 — what shipped" below.

`vitaminc-encrypt` got a cfg-based dual backend (aws-lc-rs on native, RustCrypto on wasm32) so cipherstash-suite can use AEAD types from `vitaminc::encrypt` on both targets without a feature-gate workaround. Available from vitaminc 0.2.0-pre on crates.io (vitaminc PR #163, shipped as part of the 0.2.0-pre minor-bump release).

### Layer 2 — Legacy credentials cleanup [PARTIAL]

cipherstash-client 0.34 already migrated every consumer-facing type (`ZeroKMS<C, _>`, `ScopedCipher<C>`, `CtsClient<C>`, `ZeroKMSBuilder<C>`) to the bound `for<'a> &'a C: AuthStrategy` from `stack-auth`. Nothing in 0.34 references the old `Credentials` / `AutoRefreshable` traits. The whole credentials tree was dead — kept alive only because proxy is pinned to `cipherstash-client = "0.32.2"`, predating the migration.

#### 2a — Delete the dead infrastructure [DONE]

Shipped in PR #1942. -2042 lines from cipherstash-client.

| Removed | Why |
|---|---|
| `credentials/auto_refresh` | Hosted all four `tokio::spawn` refresh loops. Replaced by `stack-auth`'s internal lazy refresh engine. |
| `credentials/user_credentials/` | OAuth device-code flow. Replaced by `stack_auth::OAuthStrategy`. |
| `credentials/service_credentials/{service_user_credentials, service_access_key_credentials}` | Replaced by `stack_auth::{OAuthStrategy, AccessKeyStrategy}`. |
| `credentials/static_credentials` | Internal helper for the deleted service-credentials code. |
| `credentials/token_store` | File-backed token cache, only used by `user_credentials`. |
| `credentials::{Credentials, AutoRefreshable, TokenExpiry}` traits | All impls were in the modules above. |
| `logger_client`, `reqwest_client` | Independently dead — defined but never imported anywhere. |
| `sleep` | tokio/std cfg-pick wrapper, only used by deleted `auto_refresh`. |

Dropped `open` and `cfg-if` deps. Verified workspace + lint + 340 cipherstash-client unit tests + wasm32 spot-check.

#### 2b — `ServiceToken` JSON contract [DEFERRED]

The legacy `cipherstash_client::credentials::ServiceToken` is intentionally retained as the only surviving piece of the credentials tree. It backs a JSON wire contract (`{accessToken, expiry}`) that protect-ffi consumes via `serde::Deserialize` from JS callers. `stack_auth::ServiceToken` doesn't impl `Deserialize` and has a different shape (wraps a `SecretToken` with eagerly-decoded JWT claims).

Migrating it requires a design decision and is **not** in this PR's scope:

- **Option A**: teach `stack_auth::ServiceToken` to deserialize from `{accessToken, expiry}` (and accept that some non-JWT tokens won't have decoded claims).
- **Option B**: protect-ffi deserializes into a thin `ServiceTokenInput` shape and converts internally.
- **Option C**: keep two ServiceToken types and document the boundary explicitly.

Worth a conversation before code changes. Until resolved, the type lives at `cipherstash_client::credentials::service_credentials::service_token::ServiceToken`.

#### 2c — Cipherstash-client release & proxy bump [PENDING]

1. Cut a cipherstash-client 0.35 release containing the current `main` (the AuthStrategy bounds + the 2a delete).
2. Proxy PR: bump to 0.35; replace `AutoRefresh::new(zerokms_config.credentials())` with `AccessKeyStrategy::builder()…build()`. The type aliases become `ZeroKMS<AccessKeyStrategy, ClientKey>` etc. The version bump alone forces this — `AutoRefresh<ServiceCredentials>` no longer exists, and the bounds require an `AuthStrategy` impl regardless.

Verified gap analysis: proxy uses no API on the old `Credentials` trait that isn't already on `AuthStrategy`. `grep` of the proxy tree finds no `clear_token` calls, no `.valid()` calls — only `get_token` semantics. `AccessKeyStrategy` is a drop-in replacement modulo the eager-vs-lazy refresh model (functionally equivalent for any active session).

### Layer 3 — `cipherstash-client` wasm cleanup

After Layer 2a, the residual blockers are small:

| Blocker | Location | Fix | Status after 2a |
|---|---|---|---|
| `tokio::time::sleep` wrapper | `src/zerokms/vitur_client/futures.rs:48` (sleep.rs gone with 2a) | Cfg-pick or replace with `gloo-timers::future::TimeoutFuture` on wasm | Reduced to 1 site |
| `std::fs` writes for local logging | `src/zerokms/local_log.rs` | Cfg-out for wasm (already feature-gated) | Unchanged |
| `std::fs` reads for config sources | `src/config/source/{cipherstash,cipherstash_secret,file}.rs`, `src/config/source/user.rs:67` (`dirs::home_dir`) | Cfg-out for wasm. Edge consumers pass config explicitly at construction time. | Unchanged |
| `reqwest` features `rustls` / `hickory-dns` / `stream` | workspace `Cargo.toml` | Wasm cfg uses `default-features = false, features = ["json"]`; reqwest's wasm32 backend dispatches to host `fetch` automatically | Unchanged |
| `reqwest-retry`, `reqwest-tracing` | workspace deps | Gate off for wasm (`reqwest-middleware` works on wasm). Audit call sites that wrap `with_retries(...)`. | Unchanged |

`stack-auth` needs its own pass — `device_code` (calls `open::that` to launch a browser) cfg-out for wasm; the access-key path is already pure-rust. `stack-profile` is filesystem-backed and only reached via OAuth flows; on wasm we drop `stack-auth/device_code` and so don't pull `stack-profile` in.

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
- [x] Layer 1 — pure crates verified on wasm32
- [~] Layer 2 — legacy credentials cleanup (2a infra delete shipped; 2b ServiceToken migration deferred; 2c release + proxy bump pending)
- [ ] Layer 3 — `cipherstash-client` wasm cleanup
- [ ] Layer 4 — `protect-wasm` bindings
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

Deleted from cipherstash-client (PR #1942):

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

- The current verification is `cargo check`, not full build. A real artifact build (e.g. `wasm-pack` or `cargo build --target wasm32-unknown-unknown --release`) will surface any link-time issues.
- `cllw-ore` requires `--no-default-features` because the default `postgres-types` feature has C deps. Consider flipping the default off in a future major version (already noted in its Cargo.toml).
- Cipherstash-client 0.35 release containing the legacy delete; proxy bump to 0.35 with `AccessKeyStrategy` migration. See Layer 2c.
- `ServiceToken` JSON contract migration (Layer 2b) — design conversation needed before code.
- Pre-existing API drift between cipherstash-client and protect-ffi (path dep) — `cipherstash_client::eql::EncryptedField` not found. Surfaces under `cargo check -p protect-ffi`. Not caused by Layer 2a; flagged for the next protect-ffi sync.
