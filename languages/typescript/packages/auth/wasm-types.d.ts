/* tslint:disable */
/* eslint-disable */

/*
 * Hand-typed overlay for the wasm-bindgen-generated bindings.
 *
 * The wasm-bindgen build emits `wasm/stack_auth_wasm.d.ts` automatically, but
 * its types are looser than we want (`Promise<any>` for `getToken`, and it
 * leaks internal `wasm-streams` types like `IntoUnderlyingByteSource` that
 * arrive transitively via reqwest's wasm32 fetch backend). This file is the
 * `types` entry for the `deno` / `worker` / `browser` / `default` conditions
 * in the `exports` map — at runtime callers load the auto-generated `.js`
 * shim, but the types they see come from here.
 *
 * The Node entry continues to use `index.d.ts`, which exposes the full surface
 * (including filesystem- and browser-backed features like the device-code flow
 * and profile-store loading) that doesn't compile to wasm32. OAuth-based
 * strategies on wasm (`OAuthStrategy`, `AutoStrategy`) are deferred to a
 * follow-up — see the Layer 3.5 notes in `wasm-analysis.md`.
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
 * Async callback used by `AccessKeyStrategy.createWithStore` to load a
 * previously-persisted token JSON. Returning `null` (or `undefined`) signals
 * "no token cached" — the strategy will fall through to re-authenticating
 * with the access key.
 */
export type LoadTokenCallback = () => Promise<string | null | undefined>

/**
 * Async callback used by `AccessKeyStrategy.createWithStore` to persist a
 * freshly-issued token JSON. The string is opaque to the caller — pass it
 * back unchanged to a future `LoadTokenCallback` (e.g. set it as a cookie
 * value, write it to a KV store, etc.).
 */
export type SaveTokenCallback = (json: string) => Promise<void>

/**
 * An auth strategy that uses a static access key for service-to-service
 * or CI/CD authentication.
 */
export declare class AccessKeyStrategy {
  private constructor()
  /** Create a new `AccessKeyStrategy` for the given region and access key. */
  static create(region: string, accessKey: string): AccessKeyStrategy
  /**
   * Create an `AccessKeyStrategy` backed by external token-store callbacks.
   *
   * The strategy consults `loadToken` on cold start before issuing any HTTP
   * request — if it returns a still-valid token, that's reused. After every
   * successful refresh or initial authentication the new token JSON is
   * written back via `saveToken`. Both callbacks return Promises so they
   * can perform async I/O (read a cookie, write to KV, etc.).
   *
   * The JSON string passed to `saveToken` contains the bearer credential
   * verbatim — treat it as secret material. End-to-end protection at rest
   * (encrypting before persistence) is a planned follow-up.
   */
  static createWithStore(
    region: string,
    accessKey: string,
    loadToken: LoadTokenCallback,
    saveToken: SaveTokenCallback,
  ): AccessKeyStrategy
  /** Retrieve a valid access token, refreshing or re-authenticating as needed. */
  getToken(): Promise<TokenResult>
  /** Release the underlying wasm resources. */
  free(): void
}
