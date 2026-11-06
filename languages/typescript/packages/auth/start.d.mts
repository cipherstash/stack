/* tslint:disable */
/* eslint-disable */

/*
 * Public TS surface for the `/start` entry — the TanStack Start adapter for
 * federated CTS tokens. Built on `csFederate` from `@cipherstash/auth/next`;
 * see `start.mjs` for the model and for why, unlike the Next.js adapter, there
 * is no request-header hand-off (and so no `csSanitizeHeaders` /
 * `csAuthHeader` here).
 *
 * `@tanstack/react-start` is an optional peer dependency: it is loaded only by
 * this entry, and its types are imported here only so the middleware this
 * entry builds is the real `createMiddleware({ type: "function" })` shape that
 * `createServerFn().middleware([...])` and `createStart`'s `functionMiddleware`
 * accept — with `context.csAuth` typed for the handler.
 */

import type { FunctionMiddlewareAfterServer } from "@tanstack/react-start";
import type { CsFederateOptions } from "./next.d.ts";
import type { WarmedAuthStrategy } from "./warmed.d.ts";
import type { TokenResult } from "./wasm-types.d.ts";

export type { CsFederateOptions } from "./next.d.ts";
export type { WarmedAuthStrategy } from "./warmed.d.ts";
export type { TokenResult } from "./wasm-types.d.ts";

/**
 * The federation options shared by every function in this entry: `csFederate`'s
 * options minus `request` and `responseHeaders`, which the Start adapter reads
 * from, and writes to, the request Start is currently handling.
 */
export type CsStartFederateOptions = Omit<
  CsFederateOptions,
  "request" | "responseHeaders"
>;

export interface CsFederationMiddlewareOptions extends CsStartFederateOptions {
  /**
   * What to do when federation fails — including the ordinary signed-out case,
   * where `getJwt` has no JWT to return and throws (or the exchange is refused).
   *
   * - `"throw"` (default): the error propagates out of the middleware, so the
   *   server function fails. Right for functions that only make sense signed in.
   * - `"null"`: the handler receives `context.csAuth === null` and decides for
   *   itself — render a signed-out state, say. Note that this folds *every*
   *   failure into `null`, a misconfigured `workspaceCrn` included; prefer
   *   `"throw"` wherever a failure should be loud.
   */
  onError?: "throw" | "null";
}

/** The server context this entry's middleware adds: `{ csAuth }`. */
export interface CsAuthContext<
  TStrategy extends WarmedAuthStrategy | null = WarmedAuthStrategy,
> {
  /**
   * The current user's federated token as a no-federation `AuthStrategy` —
   * hand it to `new Encryption({ authStrategy: context.csAuth })` from
   * `@cipherstash/stack`, or to anything else that drives a strategy.
   *
   * **It does not refresh.** `getToken()` returns the same token on every call,
   * so it is valid only until that token's TTL expires. It is scoped to the
   * server-function call that produced it: use it within the call (a detached
   * callback *within* the call is fine), never cache it across calls — the
   * middleware runs again on the next one.
   *
   * `null` only with `onError: "null"`, on the signed-out / failed path.
   */
  csAuth: TStrategy;
}

/**
 * The Start function middleware {@link csFederationMiddleware} returns — the
 * same type as `createMiddleware({ type: "function" }).server(fn)` where `fn`
 * calls `next({ context: { csAuth } })`, so it slots into
 * `createServerFn().middleware([...])` and into `createStart`'s
 * `functionMiddleware` like any middleware you wrote yourself.
 */
export type CsFederationMiddleware<
  TContext extends CsAuthContext<WarmedAuthStrategy | null>,
> = FunctionMiddlewareAfterServer<
  {},
  unknown,
  undefined,
  TContext,
  undefined,
  undefined,
  undefined
>;

/**
 * Build a Start function middleware that federates-or-reuses the current user's
 * CTS token on every server-function call and passes it to the handler as
 * `context.csAuth` ({@link CsAuthContext}).
 *
 * On each call it reads the request Start is handling (`getRequest()`), runs
 * `csFederate` against it — the per-workspace `cs_token_<workspaceId>` cookie
 * is the cross-request cache, so a reuse is cookie-only and a miss federates
 * the JWT `getJwt` returns — appends the refreshed `Set-Cookie` to Start's live
 * response headers (appended, not set, so Clerk's and Start's own cookies
 * survive), and calls `next({ context: { csAuth } })`.
 *
 * No request header carries the token, so nothing is stripped on ingress and
 * nothing can be forged from outside: the Next.js adapter's `csSanitizeHeaders`
 * / `csAuthHeader` pair, and the CIP-3112 caveat that goes with it, do not apply
 * here.
 *
 * **Throws on federation failure** by default — including the ordinary
 * signed-out case. Pass `onError: "null"` for a middleware whose handler sees
 * `context.csAuth === null` instead.
 *
 * `context.csAuth` does not refresh — see {@link CsAuthContext} for the TTL
 * boundary.
 *
 * @example
 * ```ts
 * // src/server/cs-auth.ts — one middleware, reused by every server function.
 * import { auth } from "@clerk/tanstack-react-start/server";
 * import { csFederationMiddleware } from "@cipherstash/auth/start";
 *
 * export const csAuth = csFederationMiddleware({
 *   workspaceCrn: process.env.CS_WORKSPACE_CRN!, // "crn:<region>:<workspace-id>"
 *   getJwt: async () => {
 *     // Clerk's `auth()` reads the request `clerkMiddleware()` populated in
 *     // `src/start.ts`; the template is the one you created for CipherStash.
 *     const { getToken } = await auth();
 *     const jwt = await getToken({ template: "cipherstash" });
 *     if (!jwt) throw new Error("signed out");
 *     return jwt;
 *   },
 * });
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
export declare function csFederationMiddleware(
  options: CsFederationMiddlewareOptions & { onError: "null" },
): CsFederationMiddleware<CsAuthContext<WarmedAuthStrategy | null>>;
export declare function csFederationMiddleware(
  options: CsFederationMiddlewareOptions & { onError?: "throw" },
): CsFederationMiddleware<CsAuthContext<WarmedAuthStrategy>>;

/**
 * Options for {@link csFederateRequest}: {@link CsStartFederateOptions} plus
 * the explicit `request` / `responseHeaders` pair — i.e. exactly `csFederate`'s
 * options.
 */
export interface CsFederateRequestOptions extends CsStartFederateOptions {
  /** Incoming request — the token cookie is read from its `Cookie` header. */
  request: Request;
  /** Outgoing headers — the refreshed token cookie is appended as `Set-Cookie`. */
  responseHeaders: Headers;
}

export interface CsFederateRequestResult {
  /** The federated token. */
  result: TokenResult;
  /**
   * The same token as a no-federation `AuthStrategy`. Does not refresh — valid
   * until the token's TTL expires; see {@link CsAuthContext}.
   */
  strategy: WarmedAuthStrategy;
}

/**
 * Federate-or-reuse against an explicit `request` / `responseHeaders` pair and
 * get back both the `TokenResult` and the warmed strategy — for a Start
 * *request* middleware, a route handler, or any place that already holds the
 * request and owns the response, where the function-middleware wrapper is the
 * wrong shape. Throws on failure, including the signed-out case.
 *
 * The strategy does not refresh — see {@link CsAuthContext} for the TTL
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
