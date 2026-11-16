/* tslint:disable */
/* eslint-disable */

/*
 * Public TS surface for the `/start` entry — the TanStack Start adapter for
 * federated CTS tokens. Built on `csFederate` from `@cipherstash/auth/next`;
 * see `start.mjs` for the model, for why there is no request-header hand-off
 * (and so no `csSanitizeHeaders` / `csAuthHeader` here), and for why this
 * entry exports a function to call inside a middleware rather than a
 * ready-made middleware.
 *
 * `@tanstack/react-start` is an optional peer dependency, loaded only by this
 * entry and only at runtime: these declarations name none of its types.
 *
 * This file is `.d.mts` because the entry is ESM-only, like TanStack Start.
 */

import type { CsFederateCommonOptions, CsFederateOptions } from "./next.d.ts";
import type { WarmedAuthStrategy } from "./warmed.d.ts";
import type { TokenResult } from "./wasm-types.d.ts";

export type {
  CsFederateCommonOptions,
  CsFederateOptions,
} from "./next.d.ts";
export type { WarmedAuthStrategy } from "./warmed.d.ts";
export type { TokenResult } from "./wasm-types.d.ts";

/**
 * Options for {@link csFederateCurrent}: `csFederate`'s options without
 * `request` and `responseHeaders` — the request Start is handling supplies
 * both — plus `onError`.
 */
export interface CsFederateCurrentOptions extends CsFederateCommonOptions {
  /**
   * What to do when federation fails — including the ordinary signed-out case,
   * where `getJwt` has no JWT to return and throws (or the exchange is refused).
   *
   * - `"throw"` (default): the error propagates, so the server function fails.
   *   Right for functions that only make sense signed in.
   * - `"null"`: resolves to `null`, and the handler decides for itself — render
   *   a signed-out state, say. Note that this folds *every* federation failure
   *   into `null`, a misconfigured `workspaceCrn` included; prefer `"throw"`
   *   wherever a failure should be loud.
   *
   * Misuse is never folded into `null`: an unknown `onError`, a `request` /
   * `responseHeaders` / `jar`, cookie settings that conflict with an earlier
   * call in the same request, or a call outside a Start request, throws either
   * way.
   */
  onError?: "throw" | "null";
  /** Not an option here — the request Start is handling supplies it. Use {@link csFederateRequest}. */
  request?: never;
  /** Not an option here — Start's response is written through `setCookie`. Use {@link csFederateRequest}. */
  responseHeaders?: never;
  /** Not an option here — this function passes Start's own cookie helpers. */
  jar?: never;
}

/**
 * Federate-or-reuse the current user's CTS token for the request Start is
 * handling, and return it as a {@link WarmedAuthStrategy} to hand to
 * `new Encryption({ authStrategy })` from `@cipherstash/stack`.
 *
 * It reads the request with Start's `getRequest()` and reads and writes the
 * per-workspace `cs_token_<workspaceId>` HttpOnly cookie through Start's
 * `getCookie` / `setCookie`, which merge it into the response next to the
 * cookies already there (Clerk's, Start's own). Every caller inside one request
 * shares one federation, so a render that calls several server functions pays
 * for `getJwt` and the exchange once. The first caller's `getJwt` is the one
 * asked; a later call for the same workspace and cookie with a different
 * `secure` or `sameSite` throws, since its settings could no longer be applied.
 *
 * **The cookie can only be written while the response's headers are still
 * open.** If the first federation of a request runs after Start has begun
 * streaming the response — a server function reached from a late `Suspense`
 * boundary, or from a loader promise you return without awaiting — it still
 * resolves a working strategy, but the cookie is not saved and nothing reports
 * it, so the next request federates again. Have the first call happen before
 * the response starts: an awaited loader, `beforeLoad`, or a request
 * middleware.
 *
 * **Call it inside the `.server()` callback of a middleware you declare in your
 * own code**, as below — not at module level, and not from a helper that builds
 * the middleware for you. Start keeps a server function's middleware chain in
 * the client bundle and strips each `.server()` callback with its compiler,
 * which only works where `createMiddleware().server()` is written out in your
 * module. Everything inside that callback — this import, your `getJwt`, your
 * environment reads — then stays out of the browser.
 *
 * No request header carries the token, so nothing is stripped on ingress and
 * nothing can be forged from outside: the Next.js adapter's `csSanitizeHeaders`
 * / `csAuthHeader` pair, and the CIP-3112 caveat that goes with it, do not apply
 * here.
 *
 * **The strategy does not refresh.** `getToken()` returns the same token on
 * every call, so it is valid only until that token's TTL expires. It is scoped
 * to the server-function call that produced it: use it within the call (a
 * detached callback *within* the call is fine), never cache it across calls —
 * the middleware runs again on the next one.
 *
 * **Throws on federation failure** by default — including the ordinary
 * signed-out case. Pass `onError: "null"` to get `null` instead.
 *
 * @example
 * ```ts
 * // src/server/cs-auth.ts — one middleware, reused by every server function.
 * import { auth } from "@clerk/tanstack-react-start/server";
 * import { createMiddleware } from "@tanstack/react-start";
 * import { csFederateCurrent } from "@cipherstash/auth/start";
 *
 * export const csAuth = createMiddleware({ type: "function" }).server(
 *   async ({ next }) => {
 *     const csAuth = await csFederateCurrent({
 *       workspaceCrn: process.env.CS_WORKSPACE_CRN!, // "crn:<region>:<workspace-id>"
 *       getJwt: async () => {
 *         // Clerk's `auth()` reads the request `clerkMiddleware()` populated in
 *         // `src/start.ts`; the template is the one you created for CipherStash.
 *         const { getToken } = await auth();
 *         const jwt = await getToken({ template: "cipherstash" });
 *         if (!jwt) throw new Error("signed out");
 *         return jwt;
 *       },
 *     });
 *     return next({ context: { csAuth } });
 *   },
 * );
 *
 * // src/server/secrets.ts — a server function reading the warmed strategy.
 * import { createServerFn } from "@tanstack/react-start";
 * import { Encryption } from "@cipherstash/stack";
 * import { csAuth } from "./cs-auth";
 *
 * export const loadSecret = createServerFn({ method: "GET" })
 *   .middleware([csAuth])
 *   .handler(async ({ context }) => {
 *     // `context.csAuth` is a WarmedAuthStrategy — typed, never a header.
 *     // The SDK calls getToken() as needed; the strategy is good for this call.
 *     const encryption = new Encryption({ authStrategy: context.csAuth });
 *     // ... encrypt / decrypt with `encryption` ...
 *   });
 * ```
 */
export declare function csFederateCurrent(
  options: CsFederateCurrentOptions & { onError: "null" },
): Promise<WarmedAuthStrategy | null>;
export declare function csFederateCurrent(
  options: CsFederateCurrentOptions & { onError?: "throw" },
): Promise<WarmedAuthStrategy>;
export declare function csFederateCurrent(
  options: CsFederateCurrentOptions,
): Promise<WarmedAuthStrategy | null>;

/**
 * Options for {@link csFederateRequest} — exactly `csFederate`'s, with the
 * explicit `request` / `responseHeaders` pair.
 */
export type CsFederateRequestOptions = CsFederateOptions;

export interface CsFederateRequestResult {
  /** The federated token. */
  result: TokenResult;
  /**
   * The same token as a no-federation `AuthStrategy`. Does not refresh — valid
   * until the token's TTL expires; see {@link csFederateCurrent}.
   */
  strategy: WarmedAuthStrategy;
}

/**
 * Federate-or-reuse against an explicit `request` / `responseHeaders` pair and
 * get back both the `TokenResult` and the warmed strategy — for code that
 * already holds the request and builds the response itself, such as a route
 * handler that returns its own `Response`. Throws on failure, including the
 * signed-out case. Unlike {@link csFederateCurrent} it does not share a
 * federation across callers in a request: it is handed a request, not a scope.
 *
 * The strategy does not refresh — see {@link csFederateCurrent} for the TTL
 * boundary.
 *
 * @example
 * ```ts
 * // src/routes/api/data.ts — a route handler that federates and does the work.
 * import { createFileRoute } from "@tanstack/react-router";
 * import { csFederateRequest } from "@cipherstash/auth/start";
 * import { Encryption } from "@cipherstash/stack";
 *
 * export const Route = createFileRoute("/api/data")({
 *   server: {
 *     handlers: {
 *       GET: async ({ request }) => {
 *         const responseHeaders = new Headers(); // the refreshed cookie lands here
 *         const { result, strategy } = await csFederateRequest({
 *           request,
 *           responseHeaders,
 *           workspaceCrn: process.env.CS_WORKSPACE_CRN!,
 *           getJwt: () => getSessionJwt(), // your provider's *current* JWT
 *         });
 *         const encryption = new Encryption({ authStrategy: strategy });
 *         // ... encrypt / decrypt with `encryption` ...
 *         return Response.json(
 *           { workspaceId: result.workspaceId },
 *           { headers: responseHeaders }, // copy the Set-Cookie onto the response
 *         );
 *       },
 *     },
 *   },
 * });
 * ```
 */
export declare function csFederateRequest(
  options: CsFederateRequestOptions,
): Promise<CsFederateRequestResult>;
