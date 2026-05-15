# stack-auth-wasm

WebAssembly bindings for [`stack-auth`](../). Consumed by the unified [`@cipherstash/auth`](../node/) npm package — this crate is the upstream source, not a published artifact.

Scoped to `AccessKeyStrategy` (machine-to-machine auth). `AccessKeyStrategy.create(region, accessKey)` returns a strategy; `getToken(): Promise<TokenResult>` resolves to `{ token, subject, workspaceId, issuer, services }`. Errors thrown extend `Error` with a machine-readable `.code` property (`INVALID_ACCESS_KEY`, `ACCESS_DENIED`, `EXPIRED_TOKEN`, etc.) sourced from `AuthError::error_code()` in the parent `stack-auth` crate.

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

The `@cipherstash/auth` package exposes two wasm entries built from this crate:

- `@cipherstash/auth` (default for non-Node) and `@cipherstash/auth/wasm-inline` — inline-bytes shim with the wasm embedded as base64. Zero-config in Supabase Edge, Cloudflare Workers, browsers, Deno, Bun.
- `@cipherstash/auth/wasm` — sibling-`.wasm` shim from `wasm-pack --target bundler`. Smaller bundle for consumers using a wasm-aware bundler (Vite/Webpack).

Both expose the same surface. See [`../node/README.md`](../node/README.md) for consumer-facing usage.
