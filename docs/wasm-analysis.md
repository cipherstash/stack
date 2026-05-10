# WASM / Supabase Edge support for protect-ffi + cipherstash-client

## Goal

Run encrypt/decrypt against ZeroKMS from a Supabase Edge Function (Deno runtime, single-threaded, all outbound HTTP through `fetch`, ~10MB deployable budget).

## Layered plan

The work splits cleanly into four layers, each independently shippable.

### Layer 1 — Pure crypto/protocol crates

Mostly already wasm-compatible. Crates: `recipher`, `cipherstash-core`, `cllw-ore`, `cipherstash-config`, `cts-common` (with `default-features = false`), `zerokms-protocol`.

Required changes:

- Add a wasm32 target dep entry so `getrandom` routes to `crypto.getRandomValues`:

  ```toml
  [target.'cfg(target_arch = "wasm32")'.dependencies]
  getrandom = { version = "0.2", features = ["js"] }
  ```

  Likely needed in: `cipherstash-core`, `recipher`, anywhere `rand` is pulled in transitively.

- Verify each crate builds with `cargo check --target wasm32-unknown-unknown -p <crate>`.

- Document the wasm-supported crate set in workspace docs.

### Layer 2 — `cipherstash-client`

Concrete blockers and fixes:

| Blocker | Location | Fix |
|---|---|---|
| `dirs::home_dir()` for profile path | `src/config/source/user.rs:67` | Inject profile source via trait; wasm impl reads JS-supplied config |
| `std::fs` writes | `src/zerokms/local_log.rs:35`, `src/zerokms/secret_key.rs:414-415` | Feature-gate `local_log` off for wasm; secret-key persistence becomes a trait with no-op/in-memory wasm impl |
| `open::that(...)` device-code browser | `src/credentials/user_credentials/mod.rs:70` | Gate out — no interactive OIDC in edge runtime |
| `tokio = ["full"]` | optional dep | Switch wasm to `["sync", "macros", "rt"]`; replace `tokio::time::sleep` with `gloo-timers` |
| `reqwest` features `rustls`/`hickory-dns`/`stream` | workspace Cargo.toml:97-106 | Wasm cfg uses `default-features = false, features = ["json"]` (reqwest's wasm backend dispatches to host `fetch` automatically) |
| `reqwest-retry`, `reqwest-tracing` | workspace deps | Gate off for wasm (`reqwest-middleware` works) |

Add a `wasm` feature on `cipherstash-client` that flips these.

### Layer 3 — Auth / profile

`stack-profile` is filesystem-backed (`dirs` + `gethostname` + JSON files in `~/.cipherstash/`). Two options:

1. **Trait-ify** `ProfileStore`: keep filesystem impl for native, add JS-bridged impl for wasm (caller passes config from Deno env or Supabase secrets).
2. **Skip entirely** for wasm: require credentials passed at construction. Probably right for edge — no persistent home dir anyway.

`stack-auth` device-code path (`device_code/mod.rs:274` calls `open::that`) gates out for wasm. Access-key flow stays.

### Layer 4 — FFI bindings

`protect-ffi` is built on `neon = "1"` (Node N-API). None of it compiles to wasm. New sibling crate or workspace feature `protect-wasm` using `wasm-bindgen` + `wasm-bindgen-futures`.

Surface to port: the 12 `#[neon::export]` functions in `protect-ffi/crates/protect-ffi/src/lib.rs:728-1148`.

- Tokio runtime: `new_current_thread()` only, or rely entirely on `wasm-bindgen-futures` to bridge to JS promises.
- JSON marshalling: replace neon's `Json<T>` with `JsValue` + `serde-wasm-bindgen`.

## Supabase Edge runtime specifics

- Deno-based, supports `WebAssembly.instantiate`.
- Single-threaded — no `tokio::spawn` across threads, no `rayon`.
- Outbound HTTP only via host `fetch` (reqwest's wasm backend uses this transparently).
- No filesystem, no env beyond what the function declares.
- Bundle size cap ~10MB. Crypto + reqwest + serde stack will land ~1.5–3MB stripped.
- Cold start: each invocation may be a fresh instance — token caching is in-memory and short-lived.

## Status

- [x] Analysis (this doc)
- [x] Layer 1 — pure crates verified on wasm32
- [ ] Layer 2 — `cipherstash-client` wasm feature
- [ ] Layer 3 — profile/auth boundary
- [ ] Layer 4 — `protect-wasm` bindings
- [ ] Validation in a Supabase Edge Function

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
- Workspace `vitaminc` dep dropped the default `encrypt` feature — it pulls `aws-lc-rs` (C deps that don't compile on wasm32). Server crates (`cts-domain`, `cts-web`) opt back in explicitly.
- `cts-common` gained an `aead` feature (default-on) gating the `IntoAad for WorkspaceId` impl. Wasm consumers use `default-features = false`.

Native build verified via `mise run lint`. `cts-common` unit tests: 138/138 passing.

## Known follow-ups before Layer 2

- The current verification is `cargo check`, not full build. A real artifact build (e.g. `wasm-pack` or `cargo build --target wasm32-unknown-unknown --release`) will surface any link-time issues.
- `cllw-ore` requires `--no-default-features` because the default `postgres-types` feature has C deps. Consider flipping the default off in a future major version (already noted in its Cargo.toml).
