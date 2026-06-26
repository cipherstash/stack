/* tslint:disable */
/* eslint-disable */

/*
 * Public TS surface for the `/next` entry — a runtime adapter for federated CTS
 * tokens in request/response server frameworks (built for the Next.js App
 * Router, framework-agnostic by construction). See `next.mjs` for the model.
 */

import type { TokenResult } from "./wasm-types.d.ts";

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
  /** Cookie name — pass `csTokenCookieName(workspaceId)` for the per-workspace default. */
  cookieName?: string;
  /** Cookie `Secure` flag — set `false` only for localhost HTTP dev. Default `true`. */
  secure?: boolean;
  /** Cookie `SameSite`. Default `"Lax"`. */
  sameSite?: "Strict" | "Lax" | "None";
}

/**
 * Federate-or-reuse a CTS service token, persisting it to the cookie. Use in any
 * writable, in-scope context (middleware, route handler, server action).
 */
export declare function csFederate(options: CsFederateOptions): Promise<TokenResult>;

export interface CsFederationMiddlewareOptions extends CsFederateOptions {
  /** Request header to carry the warmed token. Default {@link CS_TOKEN_HEADER}. */
  headerName?: string;
}

export interface CsFederationMiddlewareResult {
  /** The federated token. */
  result: TokenResult;
  /** Request header to forward (default {@link CS_TOKEN_HEADER}). */
  headerName: string;
  /** Encoded warmed-token payload to set on that header. */
  headerValue: string;
}

/**
 * Federate-or-reuse in middleware, returning the request header that delivers
 * the warmed token to the same-request render. Forward it via
 * `NextResponse.next({ request: { headers } })`; copy `responseHeaders`
 * (carrying `Set-Cookie`) onto the response.
 */
export declare function csFederationMiddleware(
  options: CsFederationMiddlewareOptions,
): Promise<CsFederationMiddlewareResult>;

export interface CsAuthHeaderOptions {
  /** Header to read. Default {@link CS_TOKEN_HEADER}. */
  headerName?: string;
}

/**
 * An `AuthStrategy` backed by a token a middleware already warmed — it requires
 * no federation, so consumers (incl. protect-ffi) can drive `getToken()` from
 * any context.
 */
export interface WarmedAuthStrategy {
  readonly requiresFederation: false;
  getToken(): Promise<TokenResult>;
  free(): void;
}

/**
 * Read the warmed token injected by {@link csFederationMiddleware} into an
 * `AuthStrategy`. The header is read EAGERLY and closed over, so the strategy is
 * safe to drive from a detached callback. `headers` is anything with a
 * `get(name)` method (WHATWG `Headers` or Next's `headers()`). Returns `null`
 * when no warmed token is present, so the caller can fall back to a cold
 * federation.
 */
export declare function csAuthHeader(
  headers: { get(name: string): string | null },
  options?: CsAuthHeaderOptions,
): WarmedAuthStrategy | null;

/** Encode a {@link TokenResult} into the opaque header payload. */
export declare function encodeTokenHeader(result: TokenResult): string;

/** Decode the header payload produced by {@link encodeTokenHeader}. */
export declare function decodeTokenHeader(value: string): TokenResult;
