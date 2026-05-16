/* tslint:disable */
/* eslint-disable */

/*
 * Hand-typed overlay for the raw wasm-bindgen output behind the `/wasm`
 * sub-path. Most consumers should reach for the slick wrapper at
 * `/wasm-inline` (see `wasm-inline.d.ts`) which exposes the options-object
 * API and the `cookieStore`-friendly shape. This file documents the
 * lower-level surface: a single `create(region, accessKey)` factory with
 * no built-in store wiring.
 *
 * The wasm-bindgen build emits `wasm/stack_auth_wasm.d.ts` automatically,
 * but its types are looser than we want (`Promise<any>` for `getToken`,
 * leaks internal `wasm-streams` types like `IntoUnderlyingByteSource` that
 * arrive transitively via reqwest's wasm32 fetch backend). This file is
 * the `types` entry for `/wasm` — at runtime callers load the
 * auto-generated `.js` shim, but the types they see come from here.
 *
 * The Node entry uses `index.d.ts`, which exposes the full surface
 * (including filesystem- and browser-backed features like the device-code
 * flow and profile-store loading) that doesn't compile to wasm32.
 * OAuth-based strategies on wasm (`OAuthStrategy`, `AutoStrategy`) are
 * deferred to a follow-up — see the Layer 3.5 notes in `wasm-analysis.md`.
 */

/** Error codes attached to errors thrown by this package. */
export type AuthErrorCode =
  | 'REQUEST_ERROR'
  | 'ACCESS_DENIED'
  | 'EXPIRED_TOKEN'
  | 'INVALID_GRANT'
  | 'INVALID_CLIENT'
  | 'INVALID_URL'
  | 'INVALID_REGION'
  | 'INVALID_TOKEN'
  | 'SERVER_ERROR'
  | 'NOT_AUTHENTICATED'
  | 'MISSING_WORKSPACE_CRN'
  | 'INVALID_ACCESS_KEY'
  | 'INVALID_CRN'
  | 'UNKNOWN_ERROR'

/** An error thrown by this package, enriched with a machine-readable `.code`. */
export interface AuthError extends Error {
  code: AuthErrorCode
}

/**
 * The result of a successful `getToken()` call.
 *
 * Contains the bearer credential and decoded JWT claims for service discovery.
 */
export interface TokenResult {
  /** The bearer token string (used as `Authorization: Bearer <token>`). */
  token: string
  /** The subject claim from the JWT (e.g. `"CS|auth0|user123"` or `"CS|CSAKkeyId"`). */
  subject: string
  /** The workspace identifier from the JWT. */
  workspaceId: string
  /** The issuer URL from the JWT `iss` claim (i.e. the CTS host). */
  issuer: string
  /** Service endpoint URLs from the JWT `services` claim (e.g. `{ zerokms: "https://..." }`). */
  services: Record<string, string>
}

/**
 * An auth strategy that uses a static access key for service-to-service
 * or CI/CD authentication. This is the raw bundler-target binding —
 * consumers wanting the options-object / cookie-store-friendly shape
 * should import from `/wasm-inline` instead.
 */
export declare class AccessKeyStrategy {
  private constructor()
  /** Create a new `AccessKeyStrategy` for the given region and access key. */
  static create(region: string, accessKey: string): AccessKeyStrategy
  /** Retrieve a valid access token, refreshing or re-authenticating as needed. */
  getToken(): Promise<TokenResult>
  /** Release the underlying wasm resources. */
  free(): void
}
