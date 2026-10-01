/* @ts-self-types="./cookies.d.ts" */

// Pluggable cookie-backed `TokenStore` for `@cipherstash/auth`. Works in any
// runtime that exposes WHATWG `Request` + `Headers`: Supabase Edge Functions,
// Cloudflare Workers, Bun, Deno, Node 18+, Next.js App Router. The strategy
// stays substrate-agnostic — same helper plugs into both the wasm
// `AccessKeyStrategy` (this package's `/wasm-inline` entry) and the future
// napi binding.
//
// Cookie value is base64url-encoded because the raw Token JSON contains `"`
// characters, which fall outside RFC 6265's allowed cookie-value char range
// and are rejected by spec-conformant cookie libraries (the `@std/http/cookie`
// failure that bit the supawasm spike on its first end-to-end test).

import { decodeBase64Url, encodeBase64Url } from "./base64url.mjs";

const DEFAULT_NAME = "cs_token";
const DEFAULT_PATH = "/";
const DEFAULT_SAFETY_MARGIN_SECONDS = 30;

/**
 * @typedef {object} CookieStoreOptions
 * @property {Request} request                              Incoming request to read the cookie from
 * @property {Headers} responseHeaders                      Outgoing headers to append `Set-Cookie` to
 * @property {string} [name="cs_token"]                     Cookie name
 * @property {string} [domain]                              `Domain` attribute
 * @property {string} [path="/"]                            `Path` attribute
 * @property {boolean} [secure=true]                        `Secure` flag — set to `false` only for localhost HTTP dev
 * @property {boolean} [httpOnly=true]                      `HttpOnly` flag
 * @property {"Strict" | "Lax" | "None"} [sameSite="Lax"]   `SameSite` attribute — `"None"` requires `secure: true`
 * @property {number} [expirySafetyMarginSeconds=30]        Seconds to subtract from token expiry when computing `Max-Age`
 */

/**
 * @param {CookieStoreOptions} options
 * @returns {{ load(): Promise<string | null>; save(json: string): Promise<void> }}
 */
export function cookieStore(options) {
  const {
    request,
    responseHeaders,
    name = DEFAULT_NAME,
    domain,
    path = DEFAULT_PATH,
    secure = true,
    httpOnly = true,
    sameSite = "Lax",
    expirySafetyMarginSeconds = DEFAULT_SAFETY_MARGIN_SECONDS,
  } = options;

  // Browsers reject `SameSite=None` cookies that aren't also `Secure`, so the
  // cookie would silently fail to persist. Fail fast on the misconfiguration.
  if (sameSite === "None" && !secure) {
    throw new Error(
      'cookieStore: `sameSite: "None"` requires `secure: true` — browsers drop non-Secure SameSite=None cookies.',
    );
  }

  return {
    async load() {
      const cookies = parseCookieHeader(request.headers.get("cookie"));
      const encoded = cookies[name];
      if (!encoded) return null;
      try {
        return decodeBase64Url(encoded);
      } catch {
        return null;
      }
    },
    async save(json) {
      const value = encodeBase64Url(json);
      const maxAge = maxAgeFromTokenJson(json, expirySafetyMarginSeconds);
      responseHeaders.append(
        "set-cookie",
        serializeSetCookie({
          name,
          value,
          domain,
          path,
          secure,
          httpOnly,
          sameSite,
          maxAge,
        }),
      );
    },
  };
}

// ---------------------------------------------------------------------------
// Vendored cookie parse / serialise — RFC 6265, minimal subset we need
// ---------------------------------------------------------------------------

/**
 * @param {string | null} header
 * @returns {Record<string, string>}
 */
function parseCookieHeader(header) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!header) return out;
  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const k = pair.slice(0, eq).trim();
    const v = pair.slice(eq + 1).trim();
    if (k && !(k in out)) out[k] = v;
  }
  return out;
}

/**
 * @param {{
 *   name: string;
 *   value: string;
 *   domain?: string;
 *   path?: string;
 *   secure?: boolean;
 *   httpOnly?: boolean;
 *   sameSite?: "Strict" | "Lax" | "None";
 *   maxAge?: number;
 * }} opts
 * @returns {string}
 */
function serializeSetCookie(opts) {
  const parts = [`${opts.name}=${opts.value}`];
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (typeof opts.maxAge === "number")
    parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  return parts.join("; ");
}

/**
 * @param {string} json
 * @param {number} safetyMarginSeconds
 * @returns {number | undefined}
 */
function maxAgeFromTokenJson(json, safetyMarginSeconds) {
  try {
    const parsed = JSON.parse(json);
    const expiresAt = parsed?.expires_at;
    if (typeof expiresAt !== "number") return undefined;
    const nowSeconds = Math.floor(Date.now() / 1000);
    return Math.max(0, expiresAt - nowSeconds - safetyMarginSeconds);
  } catch {
    return undefined;
  }
}
