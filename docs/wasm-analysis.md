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

### Layer 3.5 — `@cipherstash/auth` becomes wasm-capable [IN PROGRESS]

Two PRs.

**PR #1952 — `stack-auth-wasm` bindings crate [MERGED].** Adds `packages/stack-auth/wasm` as a sibling to the existing napi crate. Scoped to `AccessKeyStrategy` (M2M auth) — `getToken(): Promise<TokenResult>` returning `{ token, subject, workspaceId, issuer, services }`. Errors carry a `.code` enum matching the napi contract. OAuth-based strategies (`OAuthStrategy`, `AutoStrategy`, device-code) are deferred to a follow-up: federation and token-pinning for browser/edge contexts need design work that hasn't happened yet.

Error-code mapping is hoisted onto `AuthError::error_code()` in the parent `stack-auth` crate so this PR and the existing napi sibling can share one source of truth (napi adoption is a non-functional cleanup for a follow-up).

Build targets: `wasm-pack build --target bundler` (primary — Supabase Edge, Vite, Webpack) and `--target deno` (vanilla `deno run` only — Supabase Edge Runtime sandbox blocks `fetch('file://…')` so the deno target's auto-fetch of its `.wasm` sibling fails there; the bundler output uses `import * as wasm from "./*.wasm"` which the Edge Runtime resolves natively). Tests run via `wasm-pack test --node` — pure-logic coverage (JWT claim extraction, error-code mapping, constructor smoke). HTTP semantics stay covered by the existing native `stack-auth/node/__tests__` vitest suite. CI gains the wasm32 cargo-check + wasm-pack test step alongside the existing nextest step in `test-stack-auth.yml`.

End-to-end validated against a live Supabase Edge Function returning a real `TokenResult` from `AccessKeyStrategy.getToken()` against `ap-southeast-2.aws`. The validation surfaced three runtime issues fixed in #1952:

- `stack-auth` called `std::time::SystemTime::now()` in `token.rs` and `access_key_refresher.rs` for JWT-expiry checks. The stdlib's `wasm32-unknown-unknown` `time` module is a panicking stub. Swapped to `web_time::{SystemTime, UNIX_EPOCH}` (re-exports `std::time` on native, polyfills via JS time APIs on wasm — no behavior change off wasm).
- Rust panics on wasm surface as opaque `RuntimeError: unreachable` from bytecode offsets. Added `console_error_panic_hook` and route panics to `console.error` via a `#[wasm_bindgen(start)]` module-init function.
- `wasm-pack --target deno` doesn't work in the Supabase Edge Runtime — its sandbox blocks `fetch('file://…')`, which is how the deno target loads its sibling `.wasm`. Made `--target bundler` the primary build (uses `import * as wasm from "./*.wasm"`, which Edge resolves natively); deno target retained for vanilla `deno run`.

**PR #1953 — npm unification.** Stacks on #1952. Single `@cipherstash/auth` npm package serves Node, browser/bundler, and edge consumers from one install. Final `exports` shape (post-PRs #1958 + #1959):

| Entry | `node` condition | `default` condition |
|---|---|---|
| `.` (main) | `./index.js` (napi loader) + `./index.d.ts` | `./wasm/stack_auth_wasm.js` (bundler-target, sibling `.wasm`) + `./wasm-types.d.ts` |
| `./wasm` | — | `./wasm/stack_auth_wasm.js` (raw bundler-target shim; lower-level surface) |
| `./wasm-inline` | — | `./wasm-inline.mjs` (slick wrapper with options-object API + inline-bytes wasm via `./wasm/stack_auth_wasm_inline.js`) |
| `./cookies` | — | `./cookies.mjs` (pure-JS `cookieStore` helper for WHATWG-fetch runtimes) |

Consumer routing:
- **Node** — bare `@cipherstash/auth`, gets full napi surface (device-code, profile-store, OAuth, AccessKeyStrategy).
- **Vite / Webpack / Next.js bundler users** — bare `@cipherstash/auth`, the bundler handles the sibling `.wasm` import as an asset chunk.
- **Supabase Edge Functions, Cloudflare Workers, Bun / Deno via `npm:`** — explicit `@cipherstash/auth/wasm-inline`. Loads the base64-inlined wasm shim with zero runtime config (no `static_files`, no asset copying, no bundler plugins).

Why Edge consumers need the explicit sub-path: validating against a live Supabase Edge worker surfaced two fundamental Supabase Edge Runtime 1.73.0 constraints, plus a conditional-exports limitation that affects every Deno-resolving-`npm:` runtime:

- **Bare `.wasm` ESM imports aren't supported, and assets aren't auto-bundled.** Native `import * as wasm from "./x.wasm"` (Deno 2.x), `import bytes from "./x.wasm" with { type: "bytes" }` (modern web import attributes), and `Deno.readFile` from inside `node_modules` all fail in Edge 1.73.0 unless the `.wasm` is declared in `supabase/config.toml` via `static_files`. The inline-bytes shim base64-encodes the wasm into the JS module so no asset bundling is required — works everywhere `WebAssembly.instantiate` works.
- **No condition distinguishes Deno-via-`npm:` from Node ESM.** Deno applies `[node, import, default]` for `npm:` specifiers — the same set Node ESM applies. There's no condition we can place in the exports map that fires for Deno-via-`npm:` but not Node, so we can't route the bare `.` import to wasm-inline for Edge while keeping napi for Node ESM. Tried it (alpha.2 default-flip); Edge still hits the `node` branch first and tries to load the CJS napi loader, which has no statically-resolvable ESM named exports and fails at boot. The `./wasm-inline` sub-path bypasses the conditional walk entirely.
- **Deno's `deno`/`worker`/`browser` conditions don't fire for `npm:` specifiers.** Same root cause — for npm-distributed packages, Deno walks `[node, import, default]` only. These keys are dead weight in an `npm:` package's exports map.

Trade-off for inline: ~27% larger JS payload (~726KB vs ~572KB sibling `.js`+`.wasm`, post-`wasm-opt -Oz`) and ~50ms cold-start vs streaming compile. Acceptable for an auth surface that runs once per worker boot, not per request.

Other validation-driven fixes folded into the PR:

- `serde_wasm_bindgen::Serializer::json_compatible()` for the `TokenResultPayload` so `services: BTreeMap<String, String>` serialises as a plain JS object — `BTreeMap` defaults to JS `Map`, which `JSON.stringify` flattens to `"{}"`, dropping every entry. The `wasm-types.d.ts` overlay declares `services: Record<string, string>`, so this aligns runtime shape with declared type.
- `wasm-types.d.ts` is committed hand-written (refines `Promise<any>` → `Promise<TokenResult>`, hides wasm-streams type leakage from reqwest's fetch backend, scoped to `AccessKeyStrategy`).
- CI (`publish-auth-npm.yml`) gains a `build-wasm` job that runs wasm-pack + the inline-bytes postbuild script (`scripts/inline-wasm.mjs`); the `publish` job depends on it so every release ships the inline shim. Prerelease pipeline validated through `0.37.0-alpha.0` (bundler-target only) → `0.37.0-alpha.1` (inline added) → `0.37.0-alpha.2` (services serialization fix; also tested a default-entry flip that turned out not to help Edge consumers) → `0.37.0-alpha.3` (default-flip reverted, docs corrected) → `0.37.0-alpha.5` (TokenStore trait + wasm `createWithStore` bindings landed via PRs #1958 + #1959) → `0.37.0-alpha.6` (slick options-object API + built-in `cookieStore` helper; spike's integration code dropped to ~35 lines, three of which are stack-auth-related). All published under the `next` dist-tag.

Rationale for this layer: protect-wasm (Layer 4) will need to wrap auth strategies anyway. Establishing the wasm-bindgen toolchain, inline-bytes postbuild pattern, and the exports-map shape here on a small crate means Layer 4 doesn't absorb both the toolchain bootstrap and the encrypt/decrypt porting in the same PR.

### Layer 4 — Wasm bindings for the encrypt surface

> **Likely superseded** — see "Medium-term direction" below. Skipping straight to Layer 5-via-stack-encrypt is on the table.

Original scope: add a sibling `protect-wasm` crate in the `protectjs-ffi` repo (next to the existing `crates/protect-ffi`) using `wasm-bindgen` + `wasm-bindgen-futures` + `serde-wasm-bindgen`. Port the 9 `#[neon::export]` async functions (`new_client`, `ensure_keyset`, `encrypt`, `encrypt_bulk`, `encrypt_query`, `encrypt_query_bulk`, `decrypt`, `decrypt_bulk`, `decrypt_bulk_fallible`). Build with `wasm-pack --target bundler`. Then unify under `@cipherstash/protect-ffi` using the same conditional-exports pattern Layer 3.5 establishes.

Prereqs that don't apply to stack-auth's case:

- Bump `protectjs-ffi` from `cipherstash-client = "=0.34.1-alpha.2"` / `vitaminc = "=0.1.0-pre4.2"` to the post-Layer-3 versions (cipherstash-client 0.34.1-alpha.4+, vitaminc 0.2.0-pre+). Expect API drift to fix.
- Gate `stack-profile` use in `new_client` / `ensure_keyset` — wasm has no filesystem. Pattern: accept the client key inline as a parameter (mirroring how `OAuthStrategy.withToken` replaces `fromProfile`).
- Target-split `tokio = "full"` (pulls `mio`, doesn't compile to wasm32) — same workaround stack-auth/cipherstash-client got in PR #1944.

Estimated wasm bundle: 1.5–2.5MB unoptimised, ~800KB–1.2MB optimised. Well under the 10MB Supabase Edge cap.

### Layer 5 — Validation in a Supabase Edge Function

Deploy a real edge function that calls `protect-wasm`, encrypt/decrypt against ZeroKMS, measure:

- Bundle size vs the 10MB cap
- Cold-start latency
- Round-trip correctness against a server-side native client
- Cross-backend ciphertext compatibility — encrypt on wasm (RustCrypto), decrypt on native (aws-lc-rs), and vice versa. This is the cross-backend compat test deferred from earlier.

### Layer 6 — WASI / wazero for the Go SDK [IN PROGRESS]

Everything above targets `wasm32-unknown-unknown` for a **JavaScript host** (Supabase Edge, browsers, Deno): outbound HTTP rides the host's `fetch`, and reqwest's wasm backend, `getrandom`'s `wasm_js` backend, and `web_time` all lean on JS APIs the host provides.

The Go Encryption SDK (`goencryption`, formerly `protectgo`) has a different motivation and a different target. It ships six per-platform C static libraries linked via cgo, which forces `CGO_ENABLED=1`, a C toolchain, and a build/commit matrix per OS/arch. Compiling the client to wasm and running it under a pure-Go WebAssembly runtime — **wazero** — removes cgo entirely: one `.wasm` in the module, `CGO_ENABLED=0`, and ordinary `GOOS/GOARCH` cross-compilation.

But wazero is **not** a JS host. It targets `wasm32-wasip1` (WASI preview 1) — `target_os = "wasi"`, not `"unknown"` — and provides no `fetch`, no `web-sys`, no wasm-bindgen imports. So the JS-oriented Layers 1–5 do not transfer as-is; this is a distinct target with a distinct blocker.

**History.** PR #2099 was the beachhead: it proved the `ZeroKMSConnection` seam could be satisfied by a single host-imported function (`cipherstash_transport::transport_send`, backed by Go's `net/http`) with request assembly, error mapping, chunked concurrency and client-side key derivation all running unmodified inside the guest, and validated it end to end against a real ZeroKMS. It was written against `cipherstash-client`, which `stack-kms` / `stack-encrypt` replace, so it is not merged as-is; the reusable pieces are re-targeted by the plan below.

**The measured blocker (2026-08).** `cargo check --target wasm32-wasip1 -p stack-encrypt --no-default-features` fails on exactly two things — tokio (`Only features sync,macros,io-util,rt,time are supported on wasm`) and the `aws-lc-sys` build script — and both are pulled solely by `reqwest 0.13.4` via `stack-auth` and `stack-kms`. On wasip1 reqwest ≥ 0.13.4 selects its *native* backend (hyper / tokio-full / hickory / rustls / aws-lc-sys), where 0.13.2 selected the fetch/wasm-bindgen backend #2099 fought. There is **no** `wasm-bindgen` / `web-sys` / `js-sys` in the wasip1 tree any more. The `aws-lc-sys` failure is rustls's TLS provider inside reqwest, not the AEAD — `vitaminc-encrypt` already selects its pure-Rust `aes-gcm` backend on `cfg(target_arch = "wasm32")`, which covers wasip1. Only the network stack is missing, and it has to be out of the WASI build *by construction*, not by dead-code elimination or version pinning.

**Architecture: host-provided transport.** HTTP stays out of the wasm and is satisfied by a function the Go host provides; control stays in Rust (the "host orchestrates each step" shape was considered and rejected in #2099 because it smears the protocol state machine across the FFI). Why not HTTP inside the guest: wasip1 has no `sock_connect` (receive/accept only), so outbound TCP needs a host import regardless; TLS in the guest would mean rustls on a pure-Rust provider with embedded roots and no AES-NI, strictly worse than Go's `crypto/tls` with system roots; and `wasi:http` — the right long-term answer — is component model, which wazero does not run. The host can already read guest memory, so routing HTTP through it weakens nothing: what crosses the boundary is exactly what crosses TLS (URL, bearer token, protocol JSON). Data keys, the client key and the index key never do.

**The plan** lives in [`docs/plans/stack-encrypt-go-bindings.md`](plans/stack-encrypt-go-bindings.md): phases, the vitaminc `bindings/go` layering (`vcvalue` value model + FFI codec are reused; the stack-encrypt side is the cipher/KMS side), the frozen byte formats stack-encrypt owns, and the open decisions. Terminology fixed there: *storage format* (sealed leaf, into a database), *FFI codec* (host ↔ guest marshalling, throwaway), *transport* (HTTP, out of the process).

**Gate.** `mise run wasm:wasi-check` compiles the HTTP-free core for `wasm32-wasip1` and fails if any crate's normal-dependency tree contains a JS-host backend (`wasm-bindgen`/`web-sys`/`js-sys`) **or** the native HTTP/TLS stack (`reqwest`/`hyper`/`aws-lc-sys`). Phase 0 gates `zerokms-protocol`, `cipherstash-core`, `recipher`, `cts-common`, `cllw-ore`; Phase 1 adds `stack-auth`, `stack-kms`, `stack-encrypt` once reqwest is behind a feature in each.

## Medium-term direction — `stack-encrypt` replaces `cipherstash-client`

Layer 4 as scoped above ports the existing `protect-ffi` neon bindings to wasm. That works, but it's strictly a tactical move — the underlying `cipherstash-client` crate is the long-pole heavy dependency (full reqwest stack, EQL types, config sources, etc.), and `protect-ffi` is a thin async wrapper over it.

The cleaner long-term shape mirrors what we just did with auth:

1. **`stack-encrypt`** — a new slim crate inside cipherstash-suite, in the spirit of `stack-auth`. Pulls only what's needed for encrypt/decrypt/query against ZeroKMS. Drops the config sources, the EQL type machinery, the device-identity persistence. Backed by `stack-auth` for the credential half, by `vitaminc-encrypt` for crypto, and a minimal HTTP client for the ZeroKMS protocol calls.

2. **`stack-encrypt/node` (napi)** — replaces today's `protectjs-ffi` neon bindings. Single-crate-per-binding pattern is consistent with `stack-auth/node`.

3. **`stack-encrypt/wasm` (wasm-bindgen)** — replaces what Layer 4 would have been.

4. **Single `@cipherstash/protect` npm package** under the same conditional-exports pattern Layer 3.5 establishes.

This is a meaningfully larger piece of work than Layer 4. It involves designing the slim public API of `stack-encrypt`, porting the protect-ffi semantics, migrating downstream consumers (Drizzle / Prisma / TS-ORM integrations that currently consume `@cipherstash/protect-ffi`). It's not on the critical path for Layer 5 — a working `protect-wasm` (Layer 4 as originally scoped) can prove out Supabase Edge first, and `stack-encrypt` follows on a longer arc.

The decision point is: **does Layer 5 need to ship sooner, or do we wait and skip Layer 4 entirely?**

- *Layer 4 first*: faster path to a live Supabase Edge demo (weeks). Builds throwaway-ish bindings on top of `cipherstash-client`. Need to keep them maintained until `stack-encrypt` lands.
- *Skip to stack-encrypt*: cleaner, but Layer 5 slips by however long `stack-encrypt` takes (months). Less duplication of binding work.

Pending decision. The rest of this doc assumes Layer 4 happens for now, but every section below `## Status` should be read as conditional.

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
- [~] Layer 3.5 — `stack-auth-wasm` bindings crate (#1952) + npm unification (stacked follow-up)
- [ ] Layer 4 — wasm bindings for encrypt — **likely superseded by stack-encrypt; pending decision**
- [ ] Layer 5 — Supabase Edge validation
- [~] Layer 6 — WASI / wazero for the Go SDK: Phase 0 (gate + plan) landed; Phase 1 (`stack-auth`/`stack-kms`/`stack-encrypt` build for wasip1 without reqwest) stacked on it. Plan: `docs/plans/stack-encrypt-go-bindings.md`

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
- Workspace `vitaminc`, `vitaminc-aead`, and `vitaminc-protected` on crates.io (`0.2.0-pre` at the time; now `0.3.0`) — the first release containing the cfg-based dual backend (aws-lc-rs on native, RustCrypto on wasm32) for `vitaminc-encrypt`. Shipped via [vitaminc PR #163](https://github.com/cipherstash/vitaminc/pull/163).

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
