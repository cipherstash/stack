# @cipherstash/auth

[![npm version](https://img.shields.io/npm/v/@cipherstash/auth?style=for-the-badge)](https://www.npmjs.com/package/@cipherstash/auth)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discord](https://discord.com/invite/5qwXUFb6PB)

Authentication bindings for [CipherStash](https://cipherstash.com) services. Ships native Node.js bindings for the full surface, and a wasm build for server-side edge runtimes (Supabase Edge Functions, Cloudflare Workers).

> **Not for direct browser use.** This package is intended for server-side environments — Node.js, Edge Functions, Workers, Bun, Deno. Embedding it directly in a browser bundle would leak the access key into client-side source. The `"browser": false` field in `package.json` makes bundlers like webpack and browserify refuse browser builds; for bundlers that don't honor that convention (esbuild, Vite), don't include `@cipherstash/auth` in client-only chunks. A browser-safe shape that exposes only signed operations (no raw JWT or access key) is tracked as a separate piece of work.

## Installation

```bash
npm install @cipherstash/auth
```

The package exposes four entries:

| Entry | Use when | Loads | Surface |
|---|---|---|---|
| `@cipherstash/auth` | **Node.js** | Native napi binding for the host platform | Full surface — device-code flow, profile store, OAuth, `AccessKeyStrategy` |
| `@cipherstash/auth` | **SSR bundlers** (Vite/Webpack/Next.js targeting Node or server-side rendering) | Sibling-`.wasm` shim from `wasm-pack --target bundler` | `AccessKeyStrategy` |
| `@cipherstash/auth/wasm` | Explicit opt-in to the sibling-`.wasm` shim | Same as bundler entry above | `AccessKeyStrategy` |
| `@cipherstash/auth/wasm-inline` | **Supabase Edge Functions / Cloudflare Workers / Bun / Deno via `npm:`** — runtimes that can't auto-bundle a sibling `.wasm` | Inline-bytes shim (wasm embedded as base64) | `AccessKeyStrategy` |
| `@cipherstash/auth/cookies` | Any runtime with WHATWG `Request`/`Headers` (Edge, Workers, Bun, Deno, Node 18+, Next.js App Router) | Pure-JS helper | `cookieStore(...)` — builds a `TokenStore` from a `Request + Headers` pair |

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

Pair the `wasm-inline` entry with the `cookies` helper to back the strategy with an HTTP-only cookie. Every Edge invocation gets a fresh strategy, but the cookie keeps the issued service token alive across invocations — so only the first request pays the full round-trip to CTS:

```ts
// supabase/functions/get-token/index.ts
import { AccessKeyStrategy } from "@cipherstash/auth/wasm-inline";
import { cookieStore } from "@cipherstash/auth/cookies";

Deno.serve(async (req) => {
  const responseHeaders = new Headers({ "content-type": "application/json" });

  const strategy = AccessKeyStrategy.create(
    "ap-southeast-2.aws",
    Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
    { store: cookieStore({ request: req, responseHeaders }) },
  );

  const { token, workspaceId, services } = await strategy.getToken();
  // `token` is the bearer credential; pass as `Authorization: Bearer ${token}`
  // to ZeroKMS at `services.zerokms`.

  return new Response(
    JSON.stringify({ workspaceId, services }),
    { headers: responseHeaders },
  );
});
```

`supabase/functions/get-token/deno.json`:

```jsonc
{
  "imports": {
    "@cipherstash/auth/wasm-inline": "npm:@cipherstash/auth@^0.37/wasm-inline",
    "@cipherstash/auth/cookies":     "npm:@cipherstash/auth@^0.37/cookies"
  }
}
```

Nothing extra in `supabase/config.toml` — no `static_files`, no asset copying, no bundler plugins. The `wasm-inline` entry embeds the wasm module as base64 inside the JS shim, so it loads with zero runtime config.

`getToken()` resolves to `{ token, subject, workspaceId, issuer, services }` where `services` is a plain object (e.g. `{ zerokms: "https://..." }`).

For Cloudflare Workers the shape is identical; env access becomes `env.CS_CLIENT_ACCESS_KEY` instead of `Deno.env.get(...)`.

### Caching with `cookieStore`

`cookieStore({ request, responseHeaders })` returns a `TokenStore`:

- `load()` parses the `Cookie:` header from the request, finds `cs_token` (configurable via `name`), base64url-decodes it, and returns the JSON the strategy stored last time.
- `save(json)` happens automatically after every successful refresh / initial auth — `cookieStore` appends a `Set-Cookie` header to `responseHeaders` with the JSON base64url-encoded as the value, `HttpOnly`, `SameSite=Lax`, and `Max-Age` derived from the token's `expires_at` minus a 30-second safety margin.

Available options:

| Option | Default | Notes |
|---|---|---|
| `request` | — required — | Incoming `Request` to read the cookie from |
| `responseHeaders` | — required — | Outgoing `Headers` to append `Set-Cookie` to |
| `name` | `"cs_token"` | Cookie name |
| `domain` | unset | `Domain` attribute (host-only by default) |
| `path` | `"/"` | `Path` attribute |
| `secure` | `true` | Set `false` only for localhost HTTP dev |
| `httpOnly` | `true` | Prevents JS access — keep this on |
| `sameSite` | `"Lax"` | `"Strict"` / `"Lax"` / `"None"` |
| `expirySafetyMarginSeconds` | `30` | Seconds subtracted from `expires_at` when computing `Max-Age` |

The base64url encoding skirts RFC 6265's cookie-value char range, which would otherwise reject the `"` characters present in raw JSON.

### Rolling your own store

The `store` field accepts any `{ load, save }`-shaped object — Redis, KV stores, an in-memory `Map`, anything you'd reach for:

```ts
const strategy = AccessKeyStrategy.create(region, accessKey, {
  store: {
    async load() { return await redis.get("cs:token"); /* string | null */ },
    async save(json: string) { await redis.set("cs:token", json); },
  },
});
```

Errors thrown inside `load` / `save` are caught and logged via `console.warn` — the strategy treats them as cache misses and falls back to fresh authentication.

### Why the explicit sub-path

Bare `@cipherstash/auth` works in Node (resolves to native napi) and in wasm-aware bundlers (Vite/Webpack handle the sibling-`.wasm` import natively).

It does **not** work in Deno-resolving-`npm:` runtimes (Supabase Edge, Cloudflare Workers via `npm:`). Deno applies the `node` exports condition for `npm:` specifiers — it emulates Node for npm packages — which routes the bare import to the napi loader. That loader is a CJS module without statically-resolvable ESM named exports, so it errors at boot. There's no condition Deno applies for `npm:` packages that Node ESM doesn't, so we can't route the two apart in the exports map. The `wasm-inline` sub-path bypasses the conditional walk entirely.

Trade-off for inline: ~27% larger JS payload (~726KB vs ~572KB raw wasm + JS shim) and ~50ms cold-start vs streaming compile. Acceptable for an auth surface that runs once per worker boot.

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
| `AccessKeyStrategy.create(region, accessKey, options?)` | Build a strategy from a region and access key. Pass `{ store }` to back it with a persistent cache. |
| `strategy.getToken()` | Retrieve a valid `TokenResult`, refreshing as needed |

`TokenResult` is `{ token, subject, workspaceId, issuer, services }`.

`options.store` accepts any `{ load, save }`-shaped object:

```ts
interface TokenStore {
  load(): Promise<string | null | undefined>;  // null = cache miss
  save(json: string): Promise<void>;
}
```

The strategy calls `load` on cold start (no in-memory token); if it returns a still-fresh JSON, the strategy reuses it. Otherwise it hits CTS for a fresh token and writes it back via `save`. Stale tokens trigger a refresh and the refreshed token is persisted.

### Edge — `cookieStore`

Helper that returns a `TokenStore` backed by an HTTP-only cookie. Works in any runtime that exposes WHATWG `Request` / `Headers`. See the [Caching with `cookieStore`](#caching-with-cookiestore) section above for the option reference.

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
