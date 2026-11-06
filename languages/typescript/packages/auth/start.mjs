/* @ts-self-types="./start.d.mts" */

// TanStack Start adapter for federated CTS tokens. Built on `csFederate` from
// `./next.mjs` — the framework-agnostic federate-or-reuse core — and thinner
// than the Next.js wiring on purpose.
//
// Why there is no header hand-off here: Next.js middleware cannot pass an
// object to the render, so `/next` encodes the freshly minted token into an
// unauthenticated request header (`x-cs-cts-token`), strips the inbound one on
// ingress and decodes it again in the render — the forgery surface tracked as
// CIP-3112. A Start function middleware runs IN the server function's request
// scope and hands typed values straight to the handler through
// `next({ context })`, so the token never leaves process memory: nothing to
// encode, nothing to strip, nothing a client could forge. `csSanitizeHeaders`
// and `csAuthHeader` therefore have no counterpart in this entry.
//
// The cookie half is unchanged: the CTS token is persisted to the per-workspace
// `cs_token_<workspaceId>` HttpOnly cookie as the cross-request cache, and the
// `Set-Cookie` lands on Start's response through the live response headers.

import { createMiddleware } from "@tanstack/react-start";
// A namespace import, not named: `appendResponseHeader` exists only from Start
// 1.169 (see `appendToResponse`), and a named import of a missing ESM export
// is a link-time error on every older version this entry supports.
import * as startServer from "@tanstack/react-start/server";
import { csFederate } from "./next.mjs";
import { warmedStrategy } from "./warmed.mjs";

/**
 * @typedef {import("./start.d.mts").CsStartFederateOptions} CsStartFederateOptions
 * @typedef {import("./start.d.mts").CsFederationMiddlewareOptions} CsFederationMiddlewareOptions
 * @typedef {import("./start.d.mts").CsFederateRequestOptions} CsFederateRequestOptions
 * @typedef {import("./start.d.mts").CsFederateRequestResult} CsFederateRequestResult
 */

/**
 * Federate-or-reuse against an explicit `request` / `responseHeaders` pair and
 * return both the `TokenResult` and the warmed strategy built from it. For a
 * request middleware or a route handler that already holds the request and
 * owns the response — anywhere the function-middleware wrapper
 * ({@link csFederationMiddleware}) is the wrong shape. Throws on failure,
 * including the ordinary signed-out case, exactly like `csFederate`.
 *
 * @param {CsFederateRequestOptions} options
 * @returns {Promise<CsFederateRequestResult>}
 */
export async function csFederateRequest(options) {
  const result = await csFederate(options);
  return { result, strategy: warmedStrategy(result) };
}

/**
 * Build a Start function middleware that federates (or reuses) the current
 * user's CTS token on every server-function call and passes it to the handler
 * as `context.csAuth` — a `WarmedAuthStrategy`, or `null` on the signed-out /
 * failed path when `onError: "null"`.
 *
 * The request is read with Start's `getRequest()` and the refreshed cookie is
 * appended to Start's live response headers, so the server function needs no
 * request/response plumbing of its own.
 *
 * @param {CsFederationMiddlewareOptions} options
 */
export function csFederationMiddleware(options) {
  const { onError = "throw", ...federate } = options;
  // Validate eagerly, at module-evaluation time where the middleware is built,
  // rather than on the first request — a typo here must not surface as every
  // signed-out call 500ing (or, worse, as `csAuth: null` where a throw was
  // expected).
  if (onError !== "throw" && onError !== "null") {
    throw new TypeError(
      `csFederationMiddleware: onError must be "throw" or "null", got ${JSON.stringify(onError)}`,
    );
  }
  return createMiddleware({ type: "function" }).server(async ({ next }) => {
    const csAuth = await federateCurrentRequest(federate, onError);
    return next({ context: { csAuth } });
  });
}

/**
 * Federate-or-reuse for the request Start is currently handling. The
 * `responseHeaders` passed to `csFederate` is a scratch `Headers` this function
 * owns; whatever it collects (today: the `Set-Cookie` for the token cookie) is
 * copied onto Start's response afterwards — on the failure path too, so a
 * cookie a store wrote before a later failure is not lost.
 *
 * @param {CsStartFederateOptions} options
 * @param {"throw" | "null"} onError
 * @returns {Promise<import("./warmed.d.ts").WarmedAuthStrategy | null>}
 */
async function federateCurrentRequest(options, onError) {
  const request = startServer.getRequest();
  const responseHeaders = new Headers();
  try {
    const result = await csFederate({ ...options, request, responseHeaders });
    return warmedStrategy(result);
  } catch (error) {
    if (onError === "null") return null;
    throw error;
  } finally {
    appendToResponse(responseHeaders);
  }
}

/**
 * Append every header `csFederate` collected onto Start's response. Append,
 * never set: the only header written is `Set-Cookie`, and the response usually
 * already carries one or more — Clerk's session cookies, Start's own — that an
 * overwrite would drop. That rules out Start's `setResponseHeader(name, [..])`
 * (it deletes the name first) and `setResponseHeaders(headers)` (a `set` per
 * name).
 *
 * Which append primitive exists depends on the Start version:
 *
 * - Start 1.169 and later (`@tanstack/start-server-core` 1.169.41+):
 *   `appendResponseHeader(name, value)`. For `set-cookie` it merges into the
 *   outgoing cookies and dedupes by cookie identity (name + domain + path),
 *   exactly like `setCookie`. `getResponseHeaders()` is a read-only snapshot
 *   there — mutating it warns and changes nothing.
 * - Earlier Start, back to this entry's 1.132 floor: no `appendResponseHeader`,
 *   and `getResponseHeaders()` is the response's own mutable `Headers`, so
 *   appending to it is the one path that keeps the cookies already there.
 *
 * A `Headers` iterator yields each `Set-Cookie` as its own entry rather than
 * joining them, so iteration is the portable way to walk them (`getSetCookie()`
 * is Node 19.7+ only).
 *
 * @param {Headers} collected
 */
function appendToResponse(collected) {
  const { appendResponseHeader, getResponseHeaders } = startServer;
  if (typeof appendResponseHeader === "function") {
    for (const [name, value] of collected) {
      appendResponseHeader(name, value);
    }
    return;
  }
  const response = getResponseHeaders();
  for (const [name, value] of collected) {
    response.append(name, value);
  }
}
