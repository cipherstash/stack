# @cipherstash/auth

[![npm version](https://img.shields.io/npm/v/@cipherstash/auth?style=for-the-badge)](https://www.npmjs.com/package/@cipherstash/auth)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discord](https://discord.com/invite/5qwXUFb6PB)

Authentication bindings for [CipherStash](https://cipherstash.com) services. Ships native Node.js bindings for the full surface, and a wasm build for edge runtimes (Supabase Edge Functions, Cloudflare Workers, browsers).

## Installation

```bash
npm install @cipherstash/auth
```

The package routes to the right binary based on the consumer's runtime:

| Runtime | Loads | Surface |
|---|---|---|
| Node.js | Prebuilt native (.node) for darwin x64/arm64, linux x64/arm64 (glibc), linux x64 (musl), windows x64 | Full surface — device-code flow, profile store, access keys, OAuth |
| Supabase Edge / Cloudflare Workers / Bun / Deno / browsers | Wasm bindings (inline-bytes shim) | `AccessKeyStrategy` only (machine-to-machine auth) |

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

```ts
import { AccessKeyStrategy } from "@cipherstash/auth";

const strategy = AccessKeyStrategy.create(
  "ap-southeast-2.aws",
  Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
);

const { token, workspaceId, services } = await strategy.getToken();
// Use `token` as `Authorization: Bearer ${token}` against ZeroKMS.
```

The default entry under non-Node runtimes is an **inline-bytes** wasm shim — the wasm module is embedded as base64 in the JS, so it loads with zero runtime config. No `static_files`, no asset copying, no bundler configuration.

`getToken()` resolves to `{ token, subject, workspaceId, issuer, services }` where `services` is a plain object (e.g. `{ zerokms: "https://..." }`).

### Bundler users (Vite / Webpack / Next.js)

The default entry trades ~28% extra JS bundle for the zero-config story. Bundlers that natively understand `.wasm` imports can opt in to the smaller sibling-`.wasm` variant:

```ts
import { AccessKeyStrategy } from "@cipherstash/auth/wasm";
```

The two entries expose identical APIs.

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
