# stack-auth-wasm

WebAssembly bindings for [`stack-auth`](../). Consumed by the unified [`@cipherstash/auth`](../node/) npm package — this crate is the upstream source, not a published artifact.

Scoped to `AccessKeyStrategy` (machine-to-machine auth). Region is derived from the CRN, and every issued token's `workspace` JWT claim is verified against the CRN — a mismatch surfaces as `WORKSPACE_MISMATCH`.

The wrapped [`@cipherstash/auth/wasm-inline`](../node/wasm-inline.d.ts) entry returns a [`@byteslice/result`](https://www.npmjs.com/package/@byteslice/result) `Result`: `AccessKeyStrategy.create(...)` and `getToken()` resolve to `{ data }` on success or `{ failure }` (a discriminated `AuthFailure` tagged by `type`, carrying the live `error`, optional `help`/`url`, and per-variant payload such as `WORKSPACE_MISMATCH`'s `expected`/`actual`). The failure `type`s come from `AuthError` in the parent `stack-auth` crate. The lower-level raw `/wasm` bindings still *throw* a JS `Error` whose `.code` carries the same discriminant, with the structured failure attached as the `__authFailure` property.

OAuth strategies, device-code flow, and profile-store loading are deliberately out of scope — they need Node-only APIs (filesystem device identity, browser launching) that can't be ported to wasm32.

## Build

The npm package's `build:wasm` script orchestrates everything:

```sh
cd ../node && npm run build:wasm
```

This invokes `wasm-pack build --target bundler --out-dir ../node/wasm`, strips wasm-pack metadata, and runs `scripts/inline-wasm.mjs` to emit the inline-bytes variant. CI does the same in `.github/workflows/publish-auth-npm.yml`.

## Test

```sh
wasm-pack test --node
```

Pure-logic coverage — JWT claim extraction, services-as-plain-object serialisation, error-code mapping, constructor smoke checks. HTTP semantics are covered by the native `stack-auth/node/__tests__` vitest suite.

## Published shape

The `@cipherstash/auth` package exposes three wasm-related entries:

- `@cipherstash/auth/wasm-inline` — hand-written ESM wrapper around the inline-bytes bundle (wasm embedded as base64). Exposes the slick options-object API: `AccessKeyStrategy.create(workspaceCrn, key, { store })`. Zero-config in Supabase Edge, Cloudflare Workers, Deno, Bun.
- `@cipherstash/auth/wasm` — raw sibling-`.wasm` shim from `wasm-pack --target bundler`. Lower-level surface (no options-object wrapper) for consumers using a wasm-aware bundler (Vite/Webpack).
- `@cipherstash/auth/cookies` — pure-JS helper `cookieStore({ request, responseHeaders, ... })` returning a `TokenStore`-shaped object. No wasm dependency; works in any WHATWG-fetch runtime, and forward-compatible with the future napi binding (CIP-3113).

`AccessKeyStrategy.create()` accepts an optional `{ store }` field that takes any `{ load, save }` shape. JS callback rejections inside the store are logged via `web_sys::console::warn_2` rather than swallowed (CIP-3114). See [`../node/README.md`](../node/README.md) for consumer-facing usage and the `cookieStore` reference.
