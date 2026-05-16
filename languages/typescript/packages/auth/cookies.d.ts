/* tslint:disable */
/* eslint-disable */

/*
 * Pluggable cookie-backed `TokenStore` for `@cipherstash/auth`. Works in
 * any runtime that exposes WHATWG `Request` + `Headers`: Supabase Edge
 * Functions, Cloudflare Workers, Bun, Deno, Node 18+, Next.js App Router.
 *
 * Pair with `AccessKeyStrategy.create(region, key, { store })` from the
 * `/wasm-inline` entry (or, once CIP-3113 lands, the napi binding at the
 * main `.` entry).
 */

import type { TokenStore } from "./wasm-inline.d.ts";

export type { TokenStore };

/**
 * Configuration for {@link cookieStore}.
 */
export interface CookieStoreOptions {
  /** Incoming request — the helper reads the `Cookie:` header off this. */
  request: Request;
  /** Outgoing response headers — `Set-Cookie` is appended on every save. */
  responseHeaders: Headers;
  /** Cookie name. Default: `"cs_token"`. */
  name?: string;
  /** `Domain` attribute. Default: unset (host-only). */
  domain?: string;
  /** `Path` attribute. Default: `"/"`. */
  path?: string;
  /** `Secure` flag. Caller opts in for production. Default: `false`. */
  secure?: boolean;
  /** `HttpOnly` flag — prevents JS access. Default: `true`. */
  httpOnly?: boolean;
  /** `SameSite` attribute. Default: `"Lax"`. */
  sameSite?: "Strict" | "Lax" | "None";
  /**
   * Seconds subtracted from the token's `expires_at` when computing the
   * cookie's `Max-Age`. Ensures the cookie expires slightly before the
   * underlying token does, so loaded tokens stay usable. Default: `30`.
   */
  expirySafetyMarginSeconds?: number;
}

/**
 * Build a {@link TokenStore} backed by an HTTP-only cookie.
 *
 * @example
 * ```ts
 * import { AccessKeyStrategy } from "@cipherstash/auth/wasm-inline";
 * import { cookieStore } from "@cipherstash/auth/cookies";
 *
 * Deno.serve(async (req) => {
 *   const responseHeaders = new Headers();
 *   const strategy = AccessKeyStrategy.create(region, accessKey, {
 *     store: cookieStore({ request: req, responseHeaders }),
 *   });
 *   const result = await strategy.getToken();
 *   return new Response(JSON.stringify(result), { headers: responseHeaders });
 * });
 * ```
 */
export declare function cookieStore(options: CookieStoreOptions): TokenStore;
