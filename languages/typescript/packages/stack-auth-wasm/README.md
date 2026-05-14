# @cipherstash/stack-auth-wasm

WebAssembly bindings for [`stack-auth`](https://github.com/cipherstash/cipherstash-suite/tree/main/packages/stack-auth) — built for Supabase Edge Functions (Deno) and bundler runtimes (Vite / Webpack / Node).

This is the wasm-compatible subset of the existing [`@cipherstash/auth`](https://www.npmjs.com/package/@cipherstash/auth) napi bindings. It exposes credential and token-management primitives that work without filesystem access or browser-launching APIs.

## What's included

| Class | Purpose |
|---|---|
| `AccessKeyStrategy` | Machine-to-machine auth with a static access key |
| `OAuthStrategy.withToken` | Caller-supplied OAuth token + refresh, held in memory |
| `AutoStrategy` | Env-var-driven credential detection (no profile-store fallback on wasm) |

Each strategy exposes `getToken(): Promise<TokenResult>` returning `{ token, subject, workspaceId, issuer, services }`.

Errors thrown from this package extend `Error` with a machine-readable `.code` property (e.g. `INVALID_ACCESS_KEY`, `ACCESS_DENIED`, `EXPIRED_TOKEN`).

## What's not included

These exist in the napi bindings but cannot work on wasm32:

- `bindClientDevice` / `beginDeviceCodeFlow` — depend on filesystem device identity and browser-launching for the OAuth 2.0 device-code flow
- `OAuthStrategy.fromProfile` — reads `~/.cipherstash/auth.json`
- `AutoStrategy.detect()` profile-store fallback — on wasm `detect()` resolves only via `CS_CLIENT_ACCESS_KEY` / `CS_WORKSPACE_CRN` env vars or the explicit options argument

## Build

```sh
# Bundler target — works in Supabase Edge, Vite, Webpack, Deno with static wasm imports:
npm run build:bundler   # → pkg-bundler/

# Deno target — vanilla `deno run` (uses fetch + Deno.readFile for the .wasm sibling):
npm run build:deno      # → pkg-deno/

# Both:
npm run build
```

`wasm-pack` writes the `.wasm` artifact plus matching `.d.ts` into the chosen `pkg-*` directory.

> **Picking a target.** Use `pkg-bundler/` for Supabase Edge Functions, Vite, Webpack, Next.js, and any consumer that statically imports `.wasm` modules. Use `pkg-deno/` only for vanilla `deno run` — the Supabase Edge Runtime sandbox blocks `fetch('file://…')`, so the deno target's auto-fetch of its sibling `.wasm` fails there.

## Usage (Supabase Edge Functions)

Copy `pkg-bundler/` next to your function's `index.ts` and import relatively:

```ts
import { AccessKeyStrategy } from "./pkg-bundler/stack_auth_wasm.js";

const strategy = AccessKeyStrategy.create(
  "ap-southeast-2.aws",
  Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
);

const { token, workspaceId, services } = await strategy.getToken();
// `token` is the bearer credential; pass to ZeroKMS as `Authorization: Bearer ${token}`
```

```ts
import { OAuthStrategy } from "./pkg-bundler/stack_auth_wasm.js";

// Caller supplies an OAuth token (e.g. from request headers).
const strategy = OAuthStrategy.withToken("ap-southeast-2.aws", "my-client-id", {
  accessToken: jwt,
  refreshToken,
  tokenType: "Bearer",
  expiresAt: 1730000000,
});

const { token } = await strategy.getToken();
```

The bundler-target `stack_auth_wasm.js` uses `import * as wasm from "./stack_auth_wasm_bg.wasm"`, which the Supabase Edge Runtime resolves natively — no `fetch` of the wasm asset is required.

## Test

```sh
npm test  # runs `wasm-pack test --node`
```

Pure-logic tests (type conversions, JWT claim extraction, error-code mapping, constructor smoke checks) run under Node-hosted wasm. HTTP semantics are covered by the native `stack-auth/node/__tests__` suite — they would need a fetch shim and significantly more machinery to re-run on the wasm side, and the underlying logic is identical between the two binding crates.
