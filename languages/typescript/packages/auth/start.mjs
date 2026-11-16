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
// Why this entry exports a function to call INSIDE a middleware rather than a
// ready-made middleware: Start keeps a server function's `.middleware([...])`
// chain in the CLIENT bundle (client middleware has to run there) and relies on
// its compiler to strip each middleware's `.server(...)` callback — which it
// can only do where `createMiddleware().server()` is written out in the app's
// own module. A middleware built inside this package leaves the app's module
// with nothing to strip, so its `getJwt`, its workspace config and this
// package's inline wasm (about 1 MB) all ship to the browser; measured, not
// supposed. So the app writes the three-line `createMiddleware().server()`
// chain and calls `csFederateCurrent` inside it, where the compiler removes it
// — and the import of this module with it — from the client build.
//
// The cookie half is unchanged in substance: the CTS token is persisted to the
// per-workspace `cs_token_<workspaceId>` HttpOnly cookie as the cross-request
// cache. It is read and written through Start's own `getCookie` / `setCookie`,
// which exist unchanged on every Start this entry supports and merge the cookie
// into the response next to the ones already there (Clerk's session cookies,
// Start's own) — so there is no serialised `Set-Cookie` to copy across and no
// Start-version seam in how the response is written.

import { getCookie, getRequest, setCookie } from "@tanstack/react-start/server";
import { csFederate } from "./next.mjs";
import { warmedStrategy } from "./warmed.mjs";

/**
 * @typedef {import("./start.d.mts").CsFederateCurrentOptions} CsFederateCurrentOptions
 * @typedef {import("./start.d.mts").CsFederateRequestOptions} CsFederateRequestOptions
 * @typedef {import("./start.d.mts").CsFederateRequestResult} CsFederateRequestResult
 */

/**
 * Start's cookie helpers as a `CookieJar` (see `./cookies.d.ts`). Start's
 * `setCookie` takes cookie-es options, whose `sameSite` is lower-case.
 *
 * @type {import("./cookies.d.ts").CookieJar}
 */
const startCookies = {
  get: (name) => getCookie(name),
  set(name, value, { sameSite, ...attributes }) {
    setCookie(name, value, {
      ...attributes,
      sameSite: /** @type {"strict" | "lax" | "none"} */ (
        sameSite.toLowerCase()
      ),
    });
  },
};

/**
 * Federations already started for a request, so every caller in that request
 * shares one. A server render calls several server functions inside ONE
 * request, each running the app's middleware; without this each would ask the
 * identity provider for a JWT and exchange it with CTS again, and write the
 * cookie again. Keyed weakly on the `Request` Start is handling, so an entry
 * lives exactly as long as its request.
 *
 * @type {WeakMap<Request, Map<string, Promise<import("./wasm-types.d.ts").TokenResult>>>}
 */
const federations = new WeakMap();

/**
 * Federate-or-reuse for the request Start is currently handling, and return
 * the token as a warmed strategy — or `null` on the signed-out / failed path
 * when `onError: "null"`.
 *
 * Call it inside the `.server()` callback of a middleware the app declares
 * itself (see the module comment for why), or inside a server function or
 * route handler. It reads the request with Start's `getRequest()`, so it fails
 * outside a Start request scope — loudly, whatever `onError` says.
 *
 * @param {CsFederateCurrentOptions} options
 */
export async function csFederateCurrent(options) {
  const {
    onError = "throw",
    request: explicitRequest,
    responseHeaders,
    jar,
    ...federate
  } = options;
  // Misuse is never folded into `null`: a typo in `onError`, a cookie source
  // this function does not take, or a call outside a request scope must not
  // read as "signed out".
  if (onError !== "throw" && onError !== "null") {
    throw new TypeError(
      `csFederateCurrent: onError must be "throw" or "null", got ${JSON.stringify(onError)}`,
    );
  }
  // The declared options exclude these, but a `csFederate` options object held
  // in a variable gets past a structural check. Forwarded, they would meet the
  // Start jar in `cookieStore` and fail every call as "not both" — which
  // `onError: "null"` would then report as signed out.
  if (
    explicitRequest !== undefined ||
    responseHeaders !== undefined ||
    jar !== undefined
  ) {
    throw new TypeError(
      "csFederateCurrent: `request`, `responseHeaders` and `jar` are not options here — the request Start is handling supplies them. For an explicit request, use csFederateRequest.",
    );
  }
  const request = getRequest();
  try {
    return warmedStrategy(await federateOnce(request, federate));
  } catch (error) {
    if (onError === "null") return null;
    throw error;
  }
}

/**
 * One federation per request and cookie. A failure is forgotten, so the next
 * caller in the same request tries again rather than inheriting an error that
 * may have been transient. The first caller's `secure` / `sameSite` / `getJwt`
 * are the ones used: a later caller with the same workspace, `baseUrl` and
 * cookie name joins the federation already started.
 *
 * @param {Request} request
 * @param {Omit<CsFederateCurrentOptions, "onError">} options
 */
function federateOnce(request, options) {
  let started = federations.get(request);
  if (!started) {
    started = new Map();
    federations.set(request, started);
  }
  // What decides which token comes back: the workspace, where it is exchanged,
  // and which cookie caches it. `getJwt` is deliberately not part of the key —
  // within one request it is the same user's JWT whichever closure asks.
  const key = JSON.stringify([
    options.workspaceCrn,
    options.baseUrl ?? null,
    options.cookieName ?? null,
  ]);
  let federation = started.get(key);
  if (!federation) {
    federation = csFederate({ ...options, jar: startCookies });
    started.set(key, federation);
    const pending = federation;
    pending.catch(() => {
      if (started.get(key) === pending) started.delete(key);
    });
  }
  return federation;
}

/**
 * Federate-or-reuse against an explicit `request` / `responseHeaders` pair and
 * return both the `TokenResult` and the warmed strategy built from it. For
 * code that already holds the request and builds the response itself. Throws
 * on failure, including the ordinary signed-out case, exactly like
 * `csFederate`.
 *
 * @param {CsFederateRequestOptions} options
 * @returns {Promise<CsFederateRequestResult>}
 */
export async function csFederateRequest(options) {
  const result = await csFederate(options);
  return { result, strategy: warmedStrategy(result) };
}
