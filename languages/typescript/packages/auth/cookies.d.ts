/* tslint:disable */
/* eslint-disable */

/*
 * Pluggable cookie-backed `TokenStore` for `@cipherstash/auth`. Works in
 * any runtime that exposes WHATWG `Request` + `Headers`: Supabase Edge
 * Functions, Cloudflare Workers, Bun, Deno, Node 18+, Next.js App Router.
 *
 * Pair with `AccessKeyStrategy.create(workspaceCrn, key, { store })` from
 * the `/wasm-inline` entry (or, once the napi binding supports it, the
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
  /** `Secure` flag. Set `false` only for localhost HTTP dev. Default: `true`. */
  secure?: boolean;
  /** `HttpOnly` flag — prevents JS access. Default: `true`. */
  httpOnly?: boolean;
  /**
   * `SameSite` attribute. Default: `"Lax"`. Passing `"None"` requires
   * `secure: true` — `cookieStore` throws otherwise, since browsers drop
   * non-Secure `SameSite=None` cookies.
   */
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
 *   const created = AccessKeyStrategy.create(workspaceCrn, accessKey, {
 *     store: cookieStore({ request: req, responseHeaders }),
 *   });
 *   if (created.failure) {
 *     return new Response(created.failure.type, { status: 500, headers: responseHeaders });
 *   }
 *   // Recommended: hand `created.data` to a CipherStash SDK (see the README).
 *   // Reading the token directly, as below, is a lower-level escape hatch.
 *   const result = await created.data.getToken();
 *   if (result.failure) {
 *     return new Response(result.failure.type, { status: 500, headers: responseHeaders });
 *   }
 *   return new Response(JSON.stringify(result.data), { headers: responseHeaders });
 * });
 * ```
 */
export declare function cookieStore(options: CookieStoreOptions): TokenStore;
