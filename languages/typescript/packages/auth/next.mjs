/* @ts-self-types="./next.d.ts" */

// Runtime adapter for federated CTS tokens in request/response server
// frameworks — built for the Next.js App Router but framework-agnostic by
// construction: every function operates on WHATWG `Request` / `Headers` and
// returns plain data, so the caller does the (tiny) framework wiring
// (`NextResponse.next({ request: { headers } })`, `headers()`), and the helpers
// stay unit-testable without Next installed. Mirrors the philosophy of the
// `/cookies` helper.
//
// The model: federate-or-reuse where the request is BOTH in-scope AND can write
// cookies (middleware / route handlers / server actions), persist to a per-
// workspace HTTP-only cookie for the cross-request cache, and hand the freshly
// minted token to the same-request render via a request header — because a
// `Set-Cookie` written now is not readable in the same request.

import { decodeBase64Url, encodeBase64Url } from "./base64url.mjs";
import { cookieStore } from "./cookies.mjs";
import { OidcFederationStrategy } from "./wasm-inline.mjs";

/** Request header carrying the warmed token from middleware to the render. */
export const CS_TOKEN_HEADER = "x-cs-cts-token";

/** Per-workspace cookie name for the cached CTS token. */
export function csTokenCookieName(workspaceId) {
  return `cs_token_${workspaceId}`;
}

/**
 * @typedef {object} CsFederateOptions
 * @property {Request} request                              Incoming request (reads the token cookie)
 * @property {Headers} responseHeaders                      Outgoing headers (the refreshed cookie is appended here)
 * @property {string} workspaceCrn                          `crn:<region>:<workspace-id>`
 * @property {() => string | Promise<string>} getJwt        The OIDC JWT of this request's user (Clerk, …); asked on every call
 * @property {string} [baseUrl]                             Pin federation to a CTS host / mock (overrides region discovery)
 * @property {string} [cookieName]                          Override the cookie name (defaults to `cs_token_<workspaceId>`, derived from `workspaceCrn`)
 * @property {boolean} [secure=true]                        Cookie `Secure` flag — set `false` only for localhost HTTP dev
 * @property {"Strict" | "Lax" | "None"} [sameSite="Lax"]   Cookie `SameSite`
 */

/**
 * Federate-or-reuse a CTS service token, persisting the result to the cookie.
 * Use in any writable, in-scope context (middleware, route handler, server
 * action). Returns the `TokenResult` (`{ token, services, workspaceId, … }`).
 *
 * @param {CsFederateOptions} options
 * @returns {Promise<import("./wasm-types.d.ts").TokenResult>}
 */
export async function csFederate(options) {
  const {
    request,
    responseHeaders,
    workspaceCrn,
    getJwt,
    baseUrl,
    cookieName,
    secure,
    sameSite,
  } = options;

  // Default to the per-workspace cookie name derived from the CRN
  // (`crn:<region>:<workspace-id>`). Without this, omitting `cookieName` falls
  // back to the cookieStore default (`cs_token`), collapsing every workspace's
  // token into one cookie and causing cross-workspace cache collisions.
  const workspaceId = workspaceCrn.split(":").at(-1);
  const store = cookieStore({
    request,
    responseHeaders,
    name:
      cookieName ?? (workspaceId ? csTokenCookieName(workspaceId) : undefined),
    secure,
    sameSite,
  });
  // `create()` and `getToken()` return a `@byteslice/result` Result
  // (`{ data }` on success, `{ failure }` on error) rather than throwing. Unwrap
  // both and throw the live `failure.error`, keeping this helper's documented
  // bare-`TokenResult`/throw-on-failure contract. `create()` runs outside the
  // `try` so `free()` only fires once a strategy was actually allocated.
  const created = OidcFederationStrategy.create(workspaceCrn, getJwt, {
    store,
    baseUrl,
  });
  if (created.failure) throw created.failure.error;
  const strategy = created.data;
  try {
    const result = await strategy.getToken();
    if (result.failure) throw result.failure.error;
    return result.data;
  } finally {
    strategy.free();
  }
}

/**
 * @typedef {CsFederateOptions & { headerName?: string }} CsFederationMiddlewareOptions
 */

/**
 * @typedef {object} CsFederationMiddlewareResult
 * @property {import("./wasm-types.d.ts").TokenResult} result   The federated token
 * @property {Headers} requestHeaders                           Sanitised request headers carrying the warmed token — forward these
 * @property {string} headerName                                Request header to forward (default {@link CS_TOKEN_HEADER})
 * @property {string} headerValue                               Encoded warmed-token payload to set on that header
 */
/**
 * Federate-or-reuse in middleware, then return the request headers that deliver
 * the warmed token to the same-request render (a fresh `Set-Cookie` is not
 * readable in the same request). The caller forwards `requestHeaders` via
 * `NextResponse.next({ request: { headers: requestHeaders } })` and copies
 * `responseHeaders` (carrying `Set-Cookie`) onto the response.
 *
 * `requestHeaders` is built with {@link csSanitizeHeaders}, so the inbound
 * client-supplied warmed-token header is DELETED before the freshly minted one
 * is set — the library owns that invariant rather than trusting the caller to
 * overwrite it. On the signed-out / federation-failure path (where this function
 * throws and no warmed token exists), call {@link csSanitizeHeaders} directly so
 * the strip still happens.
 *
 * @param {CsFederationMiddlewareOptions} options
 * @returns {Promise<CsFederationMiddlewareResult>}
 */
export async function csFederationMiddleware(options) {
  const result = await csFederate(options);
  const headerName = options.headerName ?? CS_TOKEN_HEADER;
  const headerValue = encodeTokenHeader(result);
  const requestHeaders = csSanitizeHeaders(options.request, { headerName });
  requestHeaders.set(headerName, headerValue);
  return { result, requestHeaders, headerName, headerValue };
}

/**
 * Clone a request's headers with the warmed-token header REMOVED, ready to
 * forward to the render.
 *
 * SECURITY: this is the ingress strip that makes {@link csAuthHeader}
 * trustworthy. Because the warmed-token payload is unauthenticated (see
 * `csAuthHeader`), any request path on which a client-supplied
 * {@link CS_TOKEN_HEADER} survives to the render is a forgery hole — and Next.js
 * middleware `matcher`s routinely exclude paths. Run every forwarded request
 * through this (directly, or via {@link csFederationMiddleware}, which calls it
 * for you), including on the signed-out and federation-error paths.
 *
 * @param {Request | Headers} source            Incoming request (or its headers)
 * @param {CsAuthHeaderOptions} [options]       `headerName` to strip (default {@link CS_TOKEN_HEADER})
 * @returns {Headers}
 */
export function csSanitizeHeaders(source, options) {
  const headerName = options?.headerName ?? CS_TOKEN_HEADER;
  const headers = new Headers(
    source instanceof Headers ? source : source.headers,
  );
  headers.delete(headerName);
  return headers;
}

/**
 * @typedef {object} CsAuthHeaderOptions
 * @property {string} [headerName]   Header to read (default {@link CS_TOKEN_HEADER})
 */

/**
 * @typedef {object} WarmedAuthStrategy
 * @property {false} requiresFederation
 * @property {() => Promise<import("./wasm-inline.d.ts").GetTokenResult>} getToken
 * @property {() => void} free
 */

/**
 * Read the warmed token a middleware injected (via {@link csFederationMiddleware})
 * into an `AuthStrategy` whose `getToken()` resolves it. The header is read
 * EAGERLY and the value closed over, so the returned strategy can be driven
 * from a detached callback (e.g. protect-ffi) where request scope is gone.
 *
 * `headers` is anything with a `get(name)` method (a WHATWG `Headers`, or
 * Next's `headers()` result). Returns `null` when no warmed token is present,
 * so callers can fall back to a cold federation.
 *
 * LIFETIME: unlike `OidcFederationStrategy` / `AccessKeyStrategy`, this strategy
 * does NOT refresh. `getToken()` returns the same closed-over token on every
 * call, so it is only valid until that token's TTL expires — after which
 * downstream CTS/ZeroKMS calls start failing with no refresh path. It is scoped
 * to the request that warmed it: hold it no longer than the request (a detached
 * callback is fine *within* the request), and re-read the header on the next one
 * rather than caching the strategy across requests.
 *
 * SECURITY: the header payload is opaque base64url JSON, NOT authenticated. The
 * `isTokenResult` guard only rejects malformed *shape*, not a forged-but-valid
 * payload — and the shape it accepts includes an arbitrary `services` map, so a
 * forged header can also point the app at an attacker-controlled ZeroKMS
 * endpoint. The threat is therefore data/key EXFILTRATION, not just identity
 * confusion. Only trust this where the inbound client-supplied header is
 * stripped before the request reaches here — use {@link csSanitizeHeaders} (or
 * {@link csFederationMiddleware}, which applies it) on EVERY path from which
 * this function is reachable, remembering that Next.js middleware `matcher`s
 * routinely exclude paths. Cryptographically pinning the payload to the app
 * (AEAD seal/open with an app-held key) so an un-stripped header can't be forged
 * is tracked in CIP-3112.
 *
 * @param {{ get(name: string): string | null }} headers
 * @param {CsAuthHeaderOptions} [options]
 * @returns {WarmedAuthStrategy | null}
 */
export function csAuthHeader(headers, options) {
  const headerName = options?.headerName ?? CS_TOKEN_HEADER;
  const raw = headers?.get(headerName) ?? null;
  if (!raw) return null;
  let warmed;
  try {
    warmed = decodeTokenHeader(raw);
  } catch {
    return null;
  }
  // Validate the FULL TokenResult shape, not just `token`. The header is
  // attacker-influenceable (a client could send its own `x-cs-cts-token`), so a
  // malformed/spoofed payload must be rejected here rather than surfacing as
  // undefined `subject`/`workspaceId`/`issuer`/`services` fields downstream.
  if (!isTokenResult(warmed)) return null;
  // Mirror a real strategy's Result-returning `getToken()` so this warmed
  // strategy stays a drop-in wherever an `OidcFederationStrategy` /
  // `AccessKeyStrategy` is consumed (e.g. protect-ffi). The warmed token is
  // already validated, so it's always a `{ data }` success.
  return {
    requiresFederation: false,
    getToken: async () => ({ data: warmed }),
    free() {},
  };
}

/**
 * Structural guard for a decoded {@link import("./wasm-types.d.ts").TokenResult}:
 * `token`/`subject`/`workspaceId`/`issuer` are non-empty strings and `services`
 * is a NON-EMPTY string→string map. A federated CTS token always carries at
 * least one service endpoint (e.g. `zerokms`), so an empty `services` signals a
 * partial/spoofed payload — reject it here rather than let the consumer read an
 * `undefined` endpoint. Rejection is safe: the caller falls back to a cold
 * federation, which re-derives the real token.
 *
 * @param {unknown} v
 * @returns {v is import("./wasm-types.d.ts").TokenResult}
 */
function isTokenResult(v) {
  if (!v || typeof v !== "object") return false;
  for (const key of ["token", "subject", "workspaceId", "issuer"]) {
    if (typeof v[key] !== "string" || v[key].length === 0) return false;
  }
  if (!v.services || typeof v.services !== "object") return false;
  const endpoints = Object.values(v.services);
  if (endpoints.length === 0) return false;
  for (const endpoint of endpoints) {
    if (typeof endpoint !== "string") return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Header payload codec — base64url(JSON) keeps the value header-safe and opaque.
// NOTE: this is opaque, NOT authenticated — see the security caveat on
// csAuthHeader. base64url primitives are shared with `/cookies` via base64url.mjs.
// ---------------------------------------------------------------------------

/**
 * @param {import("./wasm-types.d.ts").TokenResult} result
 * @returns {string}
 */
export function encodeTokenHeader(result) {
  return encodeBase64Url(JSON.stringify(result));
}

/**
 * @param {string} value
 * @returns {import("./wasm-types.d.ts").TokenResult}
 */
export function decodeTokenHeader(value) {
  return JSON.parse(decodeBase64Url(value));
}
