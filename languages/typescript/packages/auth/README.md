# @cipherstash/auth

Authentication bindings for CipherStash services.

[![npm version](https://img.shields.io/npm/v/@cipherstash/auth?style=for-the-badge)](https://www.npmjs.com/package/@cipherstash/auth)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discord](https://discord.com/invite/5qwXUFb6PB)

Authentication bindings for [CipherStash](https://cipherstash.com) services. Ships native Node.js bindings for the full surface, and a wasm build for server-side edge runtimes (Supabase Edge Functions, Cloudflare Workers).

> **Not for direct browser use.** This package is intended for server-side environments — Node.js, Edge Functions, Workers, Bun, Deno. Embedding it directly in a browser bundle would leak the access key into client-side source. The `"browser": false` field in `package.json` makes bundlers like webpack and browserify refuse browser builds; for bundlers that don't honor that convention (esbuild, Vite), don't include `@cipherstash/auth` in client-only chunks. A browser-safe shape that exposes only signed operations (no raw JWT or access key) is tracked as a separate piece of work.

## Installation

```bash
npm install @cipherstash/auth
```

The package exposes five entries:

| Entry | Use when | Loads | Surface |
|---|---|---|---|
| `@cipherstash/auth` | **Node.js** | Native napi binding for the host platform | Full surface — device-code flow, profile store, OAuth, `AccessKeyStrategy`, `OidcFederationStrategy` |
| `@cipherstash/auth` | **SSR bundlers** (Vite/Webpack/Next.js targeting Node or server-side rendering) | Sibling-`.wasm` shim from `wasm-pack --target bundler` | `AccessKeyStrategy`, `OidcFederationStrategy` |
| `@cipherstash/auth/wasm` | Explicit opt-in to the sibling-`.wasm` shim | Same as bundler entry above | `AccessKeyStrategy`, `OidcFederationStrategy` |
| `@cipherstash/auth/wasm-inline` | **Supabase Edge Functions / Cloudflare Workers / Bun / Deno via `npm:`** — runtimes that can't auto-bundle a sibling `.wasm` | Inline-bytes shim (wasm embedded as base64) | `AccessKeyStrategy`, `OidcFederationStrategy` |
| `@cipherstash/auth/cookies` | Any runtime with WHATWG `Request`/`Headers` (Edge, Workers, Bun, Deno, Node 18+, Next.js App Router) | Pure-JS helper | `cookieStore(...)` — builds a `TokenStore` from a `Request + Headers` pair |
| `@cipherstash/auth/next` | **Next.js App Router** / request-response server frameworks | Pure-JS adapter over `OidcFederationStrategy` | `csFederationMiddleware`, `csFederate`, `csAuthHeader` — federate-or-reuse + warmed-token handoff ([details](#nextjs-app-router-adapter--cipherstashauthnext)) |

The wasm bindings expose `AccessKeyStrategy` (static M2M keys) and `OidcFederationStrategy` (federating a third-party OIDC JWT — Clerk, Supabase, … — into a CTS service token). The interactive device-code flow and profile-store loading stay Node-only — they depend on filesystem and browser-launching APIs that can't be ported to wasm.

The `wasm`, `wasm-inline`, `cookies`, and `next` entries are **ESM-only** — they target Edge/Workers/Deno/Bun runtimes that are ESM-native. From a CommonJS context, load them via dynamic `import()` rather than `require()`. Only the default `@cipherstash/auth` entry has a CJS (`node`) build.

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
import { Encryption } from "@cipherstash/stack";

Deno.serve(async (req) => {
  const responseHeaders = new Headers({ "content-type": "application/json" });

  const created = AccessKeyStrategy.create(
    Deno.env.get("CS_WORKSPACE_CRN")!,    // e.g. "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
    Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
    { store: cookieStore({ request: req, responseHeaders }) },
  );
  if (created.failure) {
    return Response.json({ error: created.failure.type }, { status: 500, headers: responseHeaders });
  }

  // Hand the strategy to a CipherStash SDK — e.g. `Encryption` from
  // `@cipherstash/stack` — which acquires and refreshes CTS tokens internally,
  // so your code never handles a raw bearer token. You don't call `getToken()`
  // yourself. (Need the token itself? See "Working with tokens directly" at the
  // end of this README.)
  const encryption = new Encryption({ authStrategy: created.data });

  // ... encrypt / decrypt with `encryption` ...
  return Response.json({ ok: true }, { headers: responseHeaders });
});
```

`supabase/functions/get-token/deno.json`:

```jsonc
{
  "imports": {
    "@cipherstash/auth/wasm-inline": "npm:@cipherstash/auth@^0.41/wasm-inline",
    "@cipherstash/auth/cookies":     "npm:@cipherstash/auth@^0.41/cookies"
  }
}
```

Nothing extra in `supabase/config.toml` — no `static_files`, no asset copying, no bundler plugins. The `wasm-inline` entry embeds the wasm module as base64 inside the JS shim, so it loads with zero runtime config.

In the recommended flow you never call `getToken()` — the SDK does, internally. If you have a lower-level need for the raw token, see [Working with tokens directly](#working-with-tokens-directly-use-with-care). Factory and token failures are handled the same way; see [Error handling](#error-handling).

For Cloudflare Workers the shape is identical; env access becomes `env.CS_CLIENT_ACCESS_KEY` instead of `Deno.env.get(...)`.

### Federating a third-party OIDC JWT — `OidcFederationStrategy`

When the end user is already signed in with a third-party OIDC provider (Clerk, Supabase, Auth0, …), `OidcFederationStrategy` exchanges their provider JWT for a CTS service token via `/api/authorise` — no access key needed:

```ts
import { OidcFederationStrategy } from "@cipherstash/auth/wasm-inline";
import { cookieStore } from "@cipherstash/auth/cookies";
import { Encryption } from "@cipherstash/stack";

Deno.serve(async (req) => {
  const responseHeaders = new Headers({ "content-type": "application/json" });

  const created = OidcFederationStrategy.create(
    Deno.env.get("CS_WORKSPACE_CRN")!, // e.g. "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
    // Returns this request's user's provider JWT — asked on every getToken().
    () => getClerkSessionToken(req),
    { store: cookieStore({ request: req, responseHeaders }) },
  );
  if (created.failure) {
    return Response.json({ error: created.failure.type }, { status: 500, headers: responseHeaders });
  }

  // As above, pass the strategy to a CipherStash SDK rather than calling
  // `getToken()` yourself — the SDK owns token acquisition and refresh.
  const encryption = new Encryption({ authStrategy: created.data });

  // ... encrypt / decrypt with `encryption` ...
  return Response.json({ ok: true }, { headers: responseHeaders });
});
```

`getJwt` is called on **every** `getToken()` and must return the JWT of the user the request is for. Build one strategy per request, as above, or per user, and capture the request in the `getJwt` closure. Do not share one strategy across requests and read the user from a request context inside `getJwt`: on the Node-native entry the binding runs `getJwt` through a napi `ThreadsafeFunction`, outside the async context (`AsyncLocalStorage`) of the `getToken()` caller, so a callback built on Clerk's `auth()` or Next.js `headers()` finds no request, or the request the strategy was created in, and exchanges that user's JWT for every caller. The strategy keeps one CTS token per distinct provider JWT (a bounded, least-recently-used cache) and exchanges a JWT only while it has no unexpired CTS token, so it never hands back another user's token for the JWT it was given — but it cannot repair a `getJwt` that names the wrong user. `/api/authorise` issues no CTS refresh token, so when a user's CTS token expires their JWT is federated again; when the provider rotates a user's JWT, the new JWT is exchanged once more. The same API is available on the Node-native entry: `const { OidcFederationStrategy } = require("@cipherstash/auth")`.

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
const strategy = AccessKeyStrategy.create(workspaceCrn, accessKey, {
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
| `AccessKeyStrategy.create(workspaceCrn, accessKey, options?)` | Build a strategy from a workspace CRN and access key (returns a `Result`). Region is derived from the CRN. Pass `{ store }` to back it with a persistent cache. The strategy verifies every issued token's `workspace` claim against the CRN — mismatch surfaces as `failure.type === "WORKSPACE_MISMATCH"`. |
| `strategy.getToken()` | Retrieve a valid token, refreshing as needed. Resolves to `{ data: TokenResult }` or `{ failure }`. |

`TokenResult` is `{ token, subject, workspaceId, issuer, services }`.

`options.store` accepts any `{ load, save }`-shaped object:

```ts
interface TokenStore {
  load(): Promise<string | null | undefined>;  // null = cache miss
  save(json: string): Promise<void>;
}
```

The strategy calls `load` when the caller's JWT has no token in memory; if it returns a still-fresh JSON that was federated from that same JWT, the strategy reuses it. Otherwise it hits CTS for a fresh token and writes it back via `save`. Stale tokens trigger a refresh and the refreshed token is persisted. A token federated from another JWT (a store shared across users, or a cookie left over from a previous sign-in on the same browser) is a cache miss, never that user's token.

### Edge — `cookieStore`

Helper that returns a `TokenStore` backed by an HTTP-only cookie. Works in any runtime that exposes WHATWG `Request` / `Headers`. See the [Caching with `cookieStore`](#caching-with-cookiestore) section above for the option reference.

## Error handling

Every fallible operation returns a [`@byteslice/result`](https://www.npmjs.com/package/@byteslice/result) `Result` instead of throwing: `{ data }` on success, `{ failure }` on a domain error. Check `result.failure` — no `try/catch` needed:

```ts
const result = await strategy.getToken();
if (result.failure) {
  console.error(result.failure.type);          // e.g. "EXPIRED_TOKEN"
  console.error(result.failure.error.message); // human-readable description
  console.error(result.failure.help);          // actionable hint, when available
} else {
  use(result.data.token);                       // result.data: TokenResult
}
```

`failure` is a discriminated union — narrow on `type` to reach per-variant fields:

```ts
const created = AccessKeyStrategy.create(workspaceCrn, accessKey);
if (created.failure) {
  if (created.failure.type === "WORKSPACE_MISMATCH") {
    console.error(`expected ${created.failure.expected}, got ${created.failure.actual}`);
  }
  return;
}
const strategy = created.data;
```

Failure `type`s: `INVALID_ACCESS_KEY`, `ACCESS_DENIED`, `EXPIRED_TOKEN`, `INVALID_GRANT`, `INVALID_CLIENT`, `INVALID_REGION`, `INVALID_URL`, `INVALID_TOKEN`, `USAGE_LIMIT_EXCEEDED`, `ORG_NOT_PROVISIONED`, `SERVER_ERROR`, `REQUEST_ERROR`, `NOT_AUTHENTICATED`, `MISSING_WORKSPACE_CRN`, `INVALID_CRN`, `WORKSPACE_MISMATCH`, `INVALID_WORKSPACE_ID`, `ALREADY_CONSUMED`, `INTERNAL_ERROR`, `CUSTOM`, `STORE_ERROR`. Each `failure` also carries the live `error: Error` and optional `help`/`url`. Only a genuine internal panic still throws.

`USAGE_LIMIT_EXCEEDED` means the organisation has exhausted its allowance for the current billing period. Retrying will not clear it — the plan has to be upgraded from the CipherStash dashboard first.

`ORG_NOT_PROVISIONED` means the organisation is not set up for usage tracking at all. There is no plan to upgrade; contact CipherStash support.

> **Migrating from the throw-based API (0.40.x and earlier):** replace
> `try { const t = await s.getToken(); … } catch (err) { err.code }`
> with `const r = await s.getToken(); if (r.failure) { r.failure.type } else { r.data }`.
> Factories (`AccessKeyStrategy.create`, `AutoStrategy.detect`,
> `OidcFederationStrategy.create`, `DeviceSessionStrategy.fromProfile`) now
> return a `Result` too, so unwrap `.data` before use.

## Working with tokens directly (use with care)

The recommended integration is to hand your strategy to a CipherStash SDK — e.g.
`Encryption` from `@cipherstash/stack`, as shown above. The SDK calls
`getToken()` internally and manages refresh, so your code never handles a raw
credential.

If you have a lower-level need, `getToken()` returns the bearer token directly.
Treat it as a secret: never log it, return it to a browser, or persist it
outside a secure store.

```ts
const result = await strategy.getToken();
if (result.failure) {
  console.error(result.failure.type);
  return;
}
const { token, workspaceId, services } = result.data;
// `token` is the bearer credential — send it as `Authorization: Bearer ${token}`
// to a CTS service (e.g. ZeroKMS at `services.zerokms`).
```

`result.data` is `{ token, subject, workspaceId, issuer, services }`, where
`services` is a plain object (e.g. `{ zerokms: "https://..." }`). See
[Error handling](#error-handling) for the failure arm.

## Next.js App Router adapter — `@cipherstash/auth/next`

The `@cipherstash/auth/next` entry adapts `OidcFederationStrategy` to
request/response server frameworks. It's built for the Next.js App Router but is
framework-agnostic by construction — every function takes a WHATWG `Request` /
`Headers` and returns plain data, so it works anywhere you can read a request and
write response headers.

**The model.** Federate a third-party OIDC JWT into a CTS service token where the
request is both *in scope* and *able to write cookies* (middleware, route
handlers, server actions), then:

- **persist** the token to a per-workspace, `HttpOnly` cookie (`cs_token_<workspace-id>`) — the cross-request cache, so later requests reuse it instead of re-federating;
- **warm** the current request's render by handing the freshly minted token forward on a request header — a `Set-Cookie` written *now* isn't readable in the *same* request, so the render can't see the cookie you just set.

### Middleware — federate, warm, refresh

`csFederationMiddleware` **throws on federation failure** — including the
ordinary signed-out case, where there's no JWT to federate. Catch it, or every
unauthenticated request 500s in middleware:

```ts
// middleware.ts
import { NextResponse } from "next/server";
import { csFederationMiddleware, csSanitizeHeaders } from "@cipherstash/auth/next";

export async function middleware(request: Request) {
  const responseHeaders = new Headers(); // the refreshed cookie is appended here

  let requestHeaders: Headers;
  try {
    ({ requestHeaders } = await csFederationMiddleware({
      request,
      responseHeaders,
      workspaceCrn: process.env.CS_WORKSPACE_CRN!, // "crn:<region>:<workspace-id>"
      getJwt: () => getSessionJwt(),               // your provider's *current* JWT (Clerk, Supabase, …)
    }));
  } catch {
    // Signed out, or federation failed — let the request through unwarmed:
    // `csAuthHeader` returns null downstream and the render falls back. Still
    // strip the header, or a client-supplied one would reach the render forgeable.
    requestHeaders = csSanitizeHeaders(request);
  }

  // Deliver the warmed token (if any) to this request's render...
  const response = NextResponse.next({ request: { headers: requestHeaders } });

  // ...and copy the refreshed `Set-Cookie` onto the response.
  responseHeaders.forEach((value, key) => response.headers.append(key, value));
  return response;
}
```

`requestHeaders` is a clone of the incoming headers with any *inbound*
`x-cs-cts-token` deleted and the freshly minted one set — the strip is done by
the library, not left to your wiring. See
[Security](#security--the-warmed-token-header-is-not-authenticated) for why that
matters.

### Reading the warmed token — Server Components, Route Handlers, protect-ffi

`csAuthHeader(headers)` reads the token the middleware warmed into an
`AuthStrategy`. The header is read *eagerly* and closed over, so the returned
strategy is safe to drive from a detached callback (e.g. protect-ffi). It returns
`null` when there's no warmed token, so you can fall back to a cold federation or
render a signed-out state.

> **This strategy does not refresh.** Unlike `OidcFederationStrategy` and
> `AccessKeyStrategy`, it hands back the *same* token on every `getToken()` — it
> is valid only until that token's TTL expires, after which downstream ZeroKMS
> calls fail with no refresh path. Treat it as request-scoped: a detached
> callback *within* the request is fine, but don't cache the strategy across
> requests — re-read the header on the next one.

```ts
import { headers } from "next/headers";
import { csAuthHeader } from "@cipherstash/auth/next";
import { Encryption } from "@cipherstash/stack";

export async function loadSecret() {
  const strategy = csAuthHeader(await headers());
  if (!strategy) throw new Error("no warmed token — signed out, or middleware didn't run");

  // Hand the strategy to a CipherStash SDK — it calls getToken() as needed.
  // (The warmed strategy itself never refreshes; it's good for this request.)
  const encryption = new Encryption({ authStrategy: strategy });
  // ... encrypt / decrypt with `encryption` ...
}
```

### Without the warmed-header handoff — `csFederate`

If you only need a token inside a single writable, in-scope context — a route
handler that both authenticates *and* does the work — skip the middleware handoff
and call `csFederate` directly. It returns a `TokenResult` and throws on failure:

```ts
// app/api/data/route.ts
import { csFederate } from "@cipherstash/auth/next";

export async function GET(request: Request) {
  const responseHeaders = new Headers();
  const token = await csFederate({
    request,
    responseHeaders,
    workspaceCrn: process.env.CS_WORKSPACE_CRN!,
    getJwt: () => getSessionJwt(),
  });
  return Response.json({ workspaceId: token.workspaceId }, { headers: responseHeaders });
}
```

### Security — the warmed-token header is not authenticated

`csAuthHeader` reads an opaque base64url(JSON) payload from a request header; it
validates the *shape* of the `TokenResult`, but the payload is **not**
cryptographically authenticated. A forged header is therefore accepted as long as
it's well-formed — and since the validated shape includes an arbitrary `services`
map, a forgery can point your app at an **attacker-controlled ZeroKMS endpoint**.
The exposure is data and key exfiltration, not merely acting as the wrong
identity.

Only trust it where the inbound, client-supplied header is stripped before the
request reaches your code. `csFederationMiddleware` does this for you — its
`requestHeaders` is built by `csSanitizeHeaders(request)`, which deletes any
inbound `x-cs-cts-token` — but that only covers requests the middleware actually
runs on:

- **Every** path from which `csAuthHeader` is reachable must be sanitised. Next.js
  middleware `matcher`s routinely exclude paths (static assets, some API routes);
  an excluded-but-reachable path is a forgery hole.
- On the signed-out / federation-error path, `csFederationMiddleware` throws, so
  call `csSanitizeHeaders(request)` yourself — as the middleware example above
  does in its `catch`.

Cryptographically pinning the payload to the app (AEAD seal/open with an app-held
key), so an un-stripped header still can't be forged, is tracked in CIP-3112.
Until that lands, the ingress strip is the *only* thing standing between an
un-matched route and a forged token — treat CIP-3112 as a prerequisite for a
production rollout rather than a nice-to-have.

### API

| Export | Description |
|---|---|
| `csFederationMiddleware(options)` | Federate-or-reuse in middleware. Returns `{ result, requestHeaders, headerName, headerValue }` — forward `requestHeaders` — and appends the refreshed cookie to `responseHeaders`. Throws on failure (incl. signed out). |
| `csFederate(options)` | Federate-or-reuse in any writable, in-scope context. Returns a `TokenResult`; throws on failure. |
| `csSanitizeHeaders(source, options?)` | Clone a `Request`/`Headers` with the warmed-token header **deleted**. The ingress strip that makes `csAuthHeader` trustworthy — use on every path it's reachable from. |
| `csAuthHeader(headers, options?)` | Read the warmed token into a no-federation `AuthStrategy`, or `null` if absent. The strategy does **not** refresh — request-scoped only. |
| `csTokenCookieName(workspaceId)` | The per-workspace cookie name, `cs_token_<workspaceId>`. |
| `CS_TOKEN_HEADER` | The default warmed-token request header, `x-cs-cts-token`. |
| `encodeTokenHeader` / `decodeTokenHeader` | The opaque base64url(JSON) header codec (used internally; exported for advanced wiring). |

`options` (shared by `csFederate` and `csFederationMiddleware`):

| Option | Default | Notes |
|---|---|---|
| `request` | — required — | Incoming `Request` (reads the token cookie) |
| `responseHeaders` | — required — | Outgoing `Headers` (the refreshed cookie is appended as `Set-Cookie`) |
| `workspaceCrn` | — required — | `crn:<region>:<workspace-id>` |
| `getJwt` | — required — | Returns the third-party OIDC JWT of this request's user (asked on every call) |
| `baseUrl` | region discovery | Pin federation to a specific CTS host / mock |
| `cookieName` | `cs_token_<workspace-id>` | Override the per-workspace cookie name |
| `secure` | `true` | Cookie `Secure` flag — set `false` only for localhost HTTP dev |
| `sameSite` | `"Lax"` | Cookie `SameSite` |
| `headerName` | `x-cs-cts-token` | (`csFederationMiddleware` only) request header to carry the warmed token |

## License

Distributed under the [PolyForm Internal Use License 1.0.0](https://polyformproject.org/licenses/internal-use/1.0.0). A full copy is bundled with this package as [`LICENSE`](./LICENSE).
