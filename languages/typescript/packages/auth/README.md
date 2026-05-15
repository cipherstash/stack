# @cipherstash/auth

[![npm version](https://img.shields.io/npm/v/@cipherstash/auth?style=for-the-badge)](https://www.npmjs.com/package/@cipherstash/auth)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discord](https://discord.com/invite/5qwXUFb6PB)

Authentication bindings for [CipherStash](https://cipherstash.com) services. Ships native Node.js bindings for the full surface, and a wasm build for edge runtimes (Supabase Edge Functions, Cloudflare Workers, browsers).

## Installation

```bash
npm install @cipherstash/auth
```

The package exposes three entries:

| Entry | Use when | Surface |
|---|---|---|
| `@cipherstash/auth` | Node.js (loads napi); Vite/Webpack/Next.js with wasm-aware bundling (loads sibling-`.wasm` shim) | Full napi surface in Node; `AccessKeyStrategy` in browsers |
| `@cipherstash/auth/wasm` | Explicit opt-in to the sibling-`.wasm` shim | `AccessKeyStrategy` |
| `@cipherstash/auth/wasm-inline` | Supabase Edge Functions, Cloudflare Workers, Bun / Deno via `npm:` — runtimes that can't auto-bundle a sibling `.wasm` | `AccessKeyStrategy` |

The wasm bindings are deliberately scoped to `AccessKeyStrategy` — OAuth, device-code flow, and profile-store features depend on Node-only APIs (filesystem, browser launching) that can't be ported.

## Node.js usage — OAuth device-code flow

```js
const { beginDeviceCodeFlow } = require("@cipherstash/auth");

const result = await beginDeviceCodeFlow(region, clientId);

// Show the user the code and URL
console.log(`Go to ${result.verificationUri} and enter code: ${result.userCode}`);

// Or open the browser automatically
result.openInBrowser();

// Wait for the user to authorize
const auth = await result.pollForToken();
console.log(`Token expires in ${auth.expiresIn} seconds`);
```

The token is saved to `~/.cipherstash/auth.json` automatically and is never exposed to JavaScript.

## Edge usage — Supabase Edge Functions / Cloudflare Workers

Use the explicit `wasm-inline` sub-path:

```ts
import { AccessKeyStrategy } from "@cipherstash/auth/wasm-inline";

const strategy = AccessKeyStrategy.create(
  "ap-southeast-2.aws",
  Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
);

const { token, workspaceId, services } = await strategy.getToken();
// Use `token` as `Authorization: Bearer ${token}` against ZeroKMS.
```

The `wasm-inline` entry embeds the wasm module as base64 inside the JS shim, so it loads with zero runtime config — no `static_files` declaration, no asset copying, no bundler plugins.

`getToken()` resolves to `{ token, subject, workspaceId, issuer, services }` where `services` is a plain object (e.g. `{ zerokms: "https://..." }`).

### Why the explicit sub-path

Bare `@cipherstash/auth` works in Node (resolves to native napi) and in wasm-aware bundlers (Vite/Webpack handle the sibling-`.wasm` import natively).

It does **not** work in Deno-resolving-`npm:` runtimes (Supabase Edge, Cloudflare Workers via `npm:`). Deno applies the `node` exports condition for `npm:` specifiers — it emulates Node for npm packages — which routes the bare import to the napi loader. That loader is a CJS module without statically-resolvable ESM named exports, so it errors at boot. There's no condition Deno applies for `npm:` packages that Node ESM doesn't, so we can't route the two apart in the exports map. The `wasm-inline` sub-path bypasses the conditional walk entirely.

Trade-off for inline: ~28% larger JS payload (~825KB vs ~645KB raw wasm + JS shim) and ~50ms cold-start vs streaming compile. Acceptable for an auth surface that runs once per worker boot.

### Bundler users (Vite / Webpack / Next.js)

Bare import is the right shape — these bundlers understand the sibling-`.wasm` reference and emit it as an asset:

```ts
import { AccessKeyStrategy } from "@cipherstash/auth";
```

If your bundler doesn't handle `.wasm` imports, fall back to `@cipherstash/auth/wasm-inline`. All three entries expose identical APIs.

## API

### Node — `beginDeviceCodeFlow(region, clientId)`

Starts the OAuth 2.0 Device Authorization flow. Returns a `Promise<DeviceCodeResult>`.

#### `DeviceCodeResult`

| Property / Method | Description |
|---|---|
| `userCode` | The code the user enters at the verification URI |
| `verificationUri` | The URL the user visits to authorize |
| `verificationUriComplete` | URL with the code pre-filled |
| `expiresIn` | Seconds until the device code expires |
| `openInBrowser()` | Opens the verification URI in the default browser |
| `pollForToken()` | Polls until the user completes authorization. Returns `Promise<AuthResult>` |

#### `AuthResult`

| Property | Description |
|---|---|
| `expiresAt` | Absolute epoch timestamp (seconds) when the token expires |
| `expiresIn` | Seconds until the token expires |

### Edge — `AccessKeyStrategy`

| Method | Description |
|---|---|
| `AccessKeyStrategy.create(region, accessKey)` | Build a strategy from a region and access key |
| `strategy.getToken()` | Retrieve a valid `TokenResult`, refreshing as needed |

`TokenResult` is `{ token, subject, workspaceId, issuer, services }`.

## Error handling

Errors thrown from this package extend `Error` with a machine-readable `.code` property:

```js
try {
  await strategy.getToken();
} catch (err) {
  console.error(err.code);    // e.g. "EXPIRED_TOKEN"
  console.error(err.message); // Human-readable description
}
```

Common codes: `INVALID_ACCESS_KEY`, `ACCESS_DENIED`, `EXPIRED_TOKEN`, `INVALID_REGION`, `INVALID_TOKEN`, `SERVER_ERROR`, `REQUEST_ERROR`.

## License

See [LICENSE](https://github.com/cipherstash/cipherstash-suite/blob/main/packages/stack-auth/LICENSE).
