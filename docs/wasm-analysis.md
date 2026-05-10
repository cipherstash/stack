# WASM / Supabase Edge support for protect-ffi + cipherstash-client

## Goal

Run encrypt/decrypt against ZeroKMS from a Supabase Edge Function (Deno runtime, single-threaded, all outbound HTTP through `fetch`, ~10MB deployable budget).

## Layered plan

Originally scoped as four layers. After looking more carefully at cipherstash-client, the dominant blockers for what was Layer 2 (`tokio::spawn` background refresh, `std::fs` token caches, `dirs`/`open` interactive auth) all live inside legacy credentials code that is **already unused** in current cipherstash-client — kept alive only because proxy is pinned to a pre-migration version. Promoting that cleanup to its own layer ahead of the wasm-specific work shrinks the remaining work substantially.

Five layers, Layer 1 already shipped:

### Layer 1 — Pure crypto/protocol crates [DONE]

Six crates compile clean for `wasm32-unknown-unknown`: `recipher`, `cipherstash-core`, `cipherstash-config`, `cllw-ore` (`--no-default-features`), `cts-common` (`--no-default-features`), `zerokms-protocol`. See "Layer 1 — what shipped" below.

`vitaminc-encrypt` got a cfg-based dual backend (aws-lc-rs on native, RustCrypto on wasm32) so cipherstash-suite can use AEAD types from `vitaminc::encrypt` on both targets without a feature-gate workaround. Currently pinned to the in-flight vitaminc branch (https://github.com/cipherstash/vitaminc/pull/163).

### Layer 2 — Legacy credentials cleanup

cipherstash-client 0.34 has already migrated every consumer-facing type (`ZeroKMS<C, _>`, `ScopedCipher<C>`, `CtsClient<C>`, `ZeroKMSBuilder<C>`) to the bound `for<'a> &'a C: AuthStrategy` from `stack-auth`. Nothing in 0.34 still references the old `Credentials` / `AutoRefreshable` traits. The whole credentials tree is dead in 0.34 — only proxy is keeping it alive, and proxy is on `cipherstash-client = "0.32.2"` from crates.io, predating the migration.

Modules to remove:

| Module | Why it can go |
|---|---|
| `credentials/auto_refresh` | Hosts all the `tokio::spawn` refresh loops. Replaced by `stack-auth`'s internal refresh engine which fires lazily on `get_token()`. |
| `credentials/user_credentials` | OAuth device-code flow. Replaced by `stack_auth::OAuthStrategy`. |
| `credentials/service_credentials` | Replaced by `stack_auth::AccessKeyStrategy`. |
| `credentials/static_credentials` | Internal helper for `service_credentials`. |
| `credentials/token_store` | File-backed token cache, only used by `user_credentials`. |
| `credentials::{Credentials, AutoRefreshable, TokenExpiry}` traits | All impls live in the modules above. |
| `logger_client`, `reqwest_client` | Independently dead — defined but never imported anywhere. |

Verified gap analysis: proxy uses no API on `Credentials` that isn't already on `AuthStrategy`. `grep` of the proxy tree finds no `clear_token` calls, no `.valid()` calls, only `get_token` semantics. `AccessKeyStrategy` is a drop-in replacement for `AutoRefresh<ServiceCredentials>` modulo the eager-vs-lazy refresh model (functionally equivalent for any active session).

Steps:

1. Cipherstash-client release containing current `main` (the AuthStrategy bounds). Call it 0.35.
2. Proxy PR: bump to 0.35; replace `AutoRefresh::new(zerokms_config.credentials())` with an `AccessKeyStrategy` build; the type aliases become `ZeroKMS<AccessKeyStrategy, ClientKey>` etc. The version bump alone forces this — `AutoRefresh<ServiceCredentials>` doesn't implement `AuthStrategy`.
3. Cipherstash-client PR: delete the modules above; drop now-unused deps (`dirs`, `open`, `stack-profile` if it falls out, `tokio` feature flag if its surface becomes empty). Protect-ffi will need a one-line import fix from `cipherstash_client::credentials::ServiceToken` (deleted) to `cipherstash_client::ServiceToken` (the `stack_auth::ServiceToken` re-export).

Steps 1 and 3 can be combined in the same release. Step 2 is independent of the legacy delete — proxy must migrate either way when it bumps versions, since the bounds changed in 0.34.

### Layer 3 — `cipherstash-client` wasm cleanup

After Layer 2 the residual blockers are small:

| Blocker | Location | Fix |
|---|---|---|
| `tokio::time::sleep` wrapper | `src/sleep.rs`, `src/zerokms/vitur_client/futures.rs:48` | Cfg-pick: native uses `tokio::time::sleep`, wasm uses `gloo-timers::future::TimeoutFuture` |
| `std::fs` writes for local logging | `src/zerokms/local_log.rs:35` | Cfg-out for wasm (already feature-gated) |
| `std::fs` reads for config sources | `src/config/source/{cipherstash,cipherstash_secret,file}.rs`, `src/config/source/user.rs:67` (`dirs::home_dir`) | Cfg-out for wasm. Edge consumers pass config explicitly at construction time. |
| `reqwest` features `rustls` / `hickory-dns` / `stream` | workspace `Cargo.toml` | Wasm cfg uses `default-features = false, features = ["json"]`; reqwest's wasm32 backend dispatches to host `fetch` automatically |
| `reqwest-retry`, `reqwest-tracing` | workspace deps | Gate off for wasm (`reqwest-middleware` works on wasm). Audit call sites that wrap `with_retries(...)`. |

`stack-auth` needs its own pass at this stage — `device_code` (calls `open::that` to launch a browser) cfg-out for wasm; the access-key path is already pure-rust. `stack-profile` is filesystem-backed and only reached via OAuth flows; on wasm we drop `stack-auth/device_code` and so don't pull `stack-profile` in.

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
- [ ] Layer 2 — legacy credentials cleanup (cipherstash-client release, proxy migration, dead-module delete)
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
- Workspace `vitaminc` deps temporarily point at the [in-flight branch](https://github.com/cipherstash/vitaminc/pull/163) that adds wasm32 support to `vitaminc-encrypt` (cfg-based dual backend: aws-lc-rs on native, RustCrypto on wasm32). Switch back to a crates.io version once that PR merges and release-plz cuts a release.

Native build verified via `mise run lint`. `cts-common` unit tests: 138/138 passing.

## Known follow-ups

- Bump the workspace `vitaminc` deps from the git branch back to a crates.io version once the [vitaminc PR](https://github.com/cipherstash/vitaminc/pull/163) lands and a release is published.
- The current verification is `cargo check`, not full build. A real artifact build (e.g. `wasm-pack` or `cargo build --target wasm32-unknown-unknown --release`) will surface any link-time issues.
- `cllw-ore` requires `--no-default-features` because the default `postgres-types` feature has C deps. Consider flipping the default off in a future major version (already noted in its Cargo.toml).
