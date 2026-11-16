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

/** The attributes {@link cookieStore} sets on the token cookie. */
export interface CookieAttributes {
  /** `Domain` attribute. Absent means host-only. */
  domain?: string;
  /** `Path` attribute. */
  path: string;
  /** `Secure` flag. */
  secure: boolean;
  /** `HttpOnly` flag. */
  httpOnly: boolean;
  /** `SameSite` attribute. */
  sameSite: "Strict" | "Lax" | "None";
  /** `Max-Age` in seconds. Absent when the token carries no expiry. */
  maxAge?: number;
}

/**
 * A place cookies are read from and written to. By default {@link cookieStore}
 * reads the `Cookie` header of a `Request` and appends `Set-Cookie` to a
 * `Headers`; pass a `CookieJar` instead when the framework owns the response
 * and has its own cookie API (TanStack Start's `getCookie` / `setCookie`,
 * Next's `cookies()`), so the framework serialises and merges the cookie.
 *
 * `get` returns the cookie's value (or nothing); `set` receives the value
 * already encoded for a cookie, plus the attributes to set. Either may be
 * async.
 */
export interface CookieJar {
  get(
    name: string,
  ): string | null | undefined | Promise<string | null | undefined>;
  set(
    name: string,
    value: string,
    attributes: CookieAttributes,
  ): void | Promise<void>;
}

/** The cookie settings shared by both ways of calling {@link cookieStore}. */
export interface CookieStoreAttributeOptions {
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
 * Configuration for {@link cookieStore}, reading and writing HTTP headers.
 */
export interface CookieStoreOptions extends CookieStoreAttributeOptions {
  /** Incoming request — the helper reads the `Cookie:` header off this. */
  request: Request;
  /** Outgoing response headers — `Set-Cookie` is appended on every save. */
  responseHeaders: Headers;
  /** Not with `request` / `responseHeaders`: a jar replaces them. */
  jar?: never;
}

/**
 * Configuration for {@link cookieStore}, reading and writing through a
 * framework's own cookie API. See {@link CookieJar}.
 */
export interface CookieJarStoreOptions extends CookieStoreAttributeOptions {
  /** The framework's cookie API. Used instead of `request` / `responseHeaders`. */
  jar: CookieJar;
  /** Not with `jar`. */
  request?: never;
  /** Not with `jar`. */
  responseHeaders?: never;
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
 *
 * Pass `jar` instead of `request` / `responseHeaders` to read and write
 * through a framework's own cookie API — see {@link CookieJar}. Passing both,
 * or neither, throws.
 */
export declare function cookieStore(
  options: CookieStoreOptions | CookieJarStoreOptions,
): TokenStore;
