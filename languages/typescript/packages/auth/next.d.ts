/* tslint:disable */
/* eslint-disable */

/*
 * Public TS surface for the `/next` entry — a runtime adapter for federated CTS
 * tokens in request/response server frameworks (built for the Next.js App
 * Router, framework-agnostic by construction). See `next.mjs` for the model.
 */

import type { TokenResult } from "./wasm-types.d.ts";
import type { GetTokenResult } from "./wasm-inline.d.ts";

export type { TokenResult } from "./wasm-types.d.ts";

/** Request header carrying the warmed token from middleware to the render. */
export declare const CS_TOKEN_HEADER: "x-cs-cts-token";

/** Per-workspace cookie name for the cached CTS token (`cs_token_<workspaceId>`). */
export declare function csTokenCookieName(workspaceId: string): string;

export interface CsFederateOptions {
  /** Incoming request — the token cookie is read from its `Cookie` header. */
  request: Request;
  /** Outgoing headers — the refreshed token cookie is appended as `Set-Cookie`. */
  responseHeaders: Headers;
  /** Workspace CRN, `crn:<region>:<workspace-id>`. */
  workspaceCrn: string;
  /** Mints the current third-party OIDC JWT (re-invoked on every re-federation). */
  getJwt: () => string | Promise<string>;
  /** Pin federation to a specific CTS host / mock, overriding region discovery. */
  baseUrl?: string;
  /**
   * Cookie name. Defaults to `cs_token_<workspace-id>` derived from
   * `workspaceCrn` (per-workspace cache). Only set this to override that name.
   */
  cookieName?: string;
  /** Cookie `Secure` flag — set `false` only for localhost HTTP dev. Default `true`. */
  secure?: boolean;
  /** Cookie `SameSite`. Default `"Lax"`. */
  sameSite?: "Strict" | "Lax" | "None";
}

/**
 * Federate-or-reuse a CTS service token, persisting it to the cookie. Use in any
 * writable, in-scope context (middleware, route handler, server action). Returns
 * a {@link TokenResult}; throws on failure. When you also need to warm the
 * same-request render, prefer {@link csFederationMiddleware}.
 *
 * @example
 * ```ts
 * // app/api/data/route.ts — federate-or-reuse directly in a Route Handler.
 * import { csFederate } from "@cipherstash/auth/next";
 *
 * export async function GET(request: Request) {
 *   const responseHeaders = new Headers(); // the refreshed cookie is appended here
 *   const token = await csFederate({
 *     request,
 *     responseHeaders,
 *     workspaceCrn: process.env.CS_WORKSPACE_CRN!, // "crn:<region>:<workspace-id>"
 *     getJwt: () => getSessionJwt(),               // your provider's *current* JWT
 *   });
 *   return Response.json({ workspaceId: token.workspaceId }, { headers: responseHeaders });
 * }
 * ```
 */
export declare function csFederate(options: CsFederateOptions): Promise<TokenResult>;

export interface CsFederationMiddlewareOptions extends CsFederateOptions {
  /** Request header to carry the warmed token. Default {@link CS_TOKEN_HEADER}. */
  headerName?: string;
}

export interface CsFederationMiddlewareResult {
  /** The federated token. */
  result: TokenResult;
  /**
   * Request headers to forward: a clone of the incoming headers with any
   * client-supplied warmed-token header **stripped** (see
   * {@link csSanitizeHeaders}) and the freshly minted one set.
   */
  requestHeaders: Headers;
  /** Request header to forward (default {@link CS_TOKEN_HEADER}). */
  headerName: string;
  /** Encoded warmed-token payload to set on that header. */
  headerValue: string;
}

/**
 * Federate-or-reuse in middleware, returning the request headers that deliver
 * the warmed token to the same-request render (a `Set-Cookie` written now is not
 * readable in the same request). Forward `requestHeaders` via
 * `NextResponse.next({ request: { headers: requestHeaders } })`; copy
 * `responseHeaders` (carrying `Set-Cookie`) onto the response. Read it back with
 * {@link csAuthHeader}.
 *
 * `requestHeaders` has the inbound client-supplied warmed-token header stripped
 * ({@link csSanitizeHeaders}) before the minted one is set, so the forgery
 * invariant lives in the library rather than in the caller's wiring.
 *
 * **Throws on federation failure** — including the ordinary signed-out case
 * (no JWT to federate). Wrap it, or an unauthenticated request 500s in
 * middleware; the example below shows the signed-out fallback.
 *
 * @example
 * ```ts
 * // middleware.ts — federate once per request, warm the render, refresh the cookie.
 * import { NextResponse } from "next/server";
 * import { csFederationMiddleware, csSanitizeHeaders } from "@cipherstash/auth/next";
 *
 * export async function middleware(request: Request) {
 *   const responseHeaders = new Headers();
 *
 *   let requestHeaders: Headers;
 *   try {
 *     ({ requestHeaders } = await csFederationMiddleware({
 *       request,
 *       responseHeaders,
 *       workspaceCrn: process.env.CS_WORKSPACE_CRN!,
 *       getJwt: () => getSessionJwt(), // your provider's *current* JWT (Clerk, Supabase, …)
 *     }));
 *   } catch {
 *     // Signed out, or federation failed — let the request through unwarmed.
 *     // `csAuthHeader` returns null downstream, so the render falls back.
 *     // Still strip the header: an un-stripped inbound one would be forgeable.
 *     requestHeaders = csSanitizeHeaders(request);
 *   }
 *
 *   // Deliver the warmed token (if any) to this request's render...
 *   const response = NextResponse.next({ request: { headers: requestHeaders } });
 *
 *   // ...and copy the refreshed `Set-Cookie` onto the response.
 *   responseHeaders.forEach((value, key) => response.headers.append(key, value));
 *   return response;
 * }
 * ```
 */
export declare function csFederationMiddleware(
  options: CsFederationMiddlewareOptions,
): Promise<CsFederationMiddlewareResult>;

export interface CsAuthHeaderOptions {
  /** Header to read. Default {@link CS_TOKEN_HEADER}. */
  headerName?: string;
}

/**
 * Clone a request's headers with the warmed-token header removed, ready to
 * forward to the render.
 *
 * SECURITY: this is the ingress strip that makes {@link csAuthHeader}
 * trustworthy. Any path on which a client-supplied {@link CS_TOKEN_HEADER}
 * survives to the render is a forgery hole, and Next.js middleware `matcher`s
 * routinely exclude paths — so run every forwarded request through this
 * (directly, or via {@link csFederationMiddleware}, which applies it), including
 * on the signed-out and federation-error paths.
 */
export declare function csSanitizeHeaders(
  source: Request | Headers,
  options?: CsAuthHeaderOptions,
): Headers;

/**
 * An `AuthStrategy` backed by a token a middleware already warmed — it requires
 * no federation, so consumers (incl. protect-ffi) can drive `getToken()` from
 * any context. `getToken()` returns the same `Result` shape as a real strategy
 * (always a `{ data }` success here, since the warmed token is pre-validated),
 * so this stays a drop-in wherever an `OidcFederationStrategy` is consumed.
 *
 * **It does not refresh.** Unlike `OidcFederationStrategy` / `AccessKeyStrategy`,
 * `getToken()` hands back the *same* token every time, so the strategy is valid
 * only until that token's TTL expires — after which downstream CTS/ZeroKMS calls
 * fail with no refresh path. Treat it as request-scoped: a detached callback
 * within the request is fine, but don't cache it across requests — re-read the
 * header (or federate) on the next one.
 */
export interface WarmedAuthStrategy {
  readonly requiresFederation: false;
  getToken(): Promise<GetTokenResult>;
  free(): void;
}

/**
 * Read the warmed token injected by {@link csFederationMiddleware} into an
 * `AuthStrategy`. The header is read EAGERLY and closed over, so the strategy is
 * safe to drive from a detached callback. `headers` is anything with a
 * `get(name)` method (WHATWG `Headers` or Next's `headers()`). Returns `null`
 * when no warmed token is present, so the caller can fall back to a cold
 * federation.
 *
 * The returned strategy does not refresh — see {@link WarmedAuthStrategy} for
 * the TTL boundary.
 *
 * SECURITY: the header payload is opaque base64url(JSON), NOT authenticated —
 * only trust it where the inbound client-supplied header is stripped on ingress
 * ({@link csSanitizeHeaders}, which {@link csFederationMiddleware} applies for
 * you), on *every* path this is reachable from. A forged payload carries an
 * arbitrary `services` map, so it can point the app at an attacker-controlled
 * ZeroKMS endpoint — an exfiltration vector, not just identity confusion.
 * AEAD-sealing the payload is tracked in CIP-3112.
 *
 * @example
 * ```ts
 * // A Server Component / Route Handler reading the token the middleware warmed.
 * import { headers } from "next/headers";
 * import { csAuthHeader } from "@cipherstash/auth/next";
 * import { Encryption } from "@cipherstash/stack";
 *
 * export async function loadSecret() {
 *   const strategy = csAuthHeader(await headers());
 *   if (!strategy) throw new Error("no warmed token — signed out, or middleware didn't run");
 *
 *   // Hand the strategy to a CipherStash SDK — it calls getToken() as needed.
 *   // (The warmed strategy itself never refreshes; it's good for this request.)
 *   const encryption = new Encryption({ authStrategy: strategy });
 *   // ... encrypt / decrypt with `encryption` ...
 * }
 * ```
 */
export declare function csAuthHeader(
  headers: { get(name: string): string | null },
  options?: CsAuthHeaderOptions,
): WarmedAuthStrategy | null;

/** Encode a {@link TokenResult} into the opaque header payload. */
export declare function encodeTokenHeader(result: TokenResult): string;

/** Decode the header payload produced by {@link encodeTokenHeader}. */
export declare function decodeTokenHeader(value: string): TokenResult;
