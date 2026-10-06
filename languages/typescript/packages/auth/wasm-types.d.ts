/* tslint:disable */
/* eslint-disable */

/*
 * Hand-typed overlay for the raw wasm-bindgen output behind the `/wasm`
 * sub-path. Most consumers should reach for the slick wrapper at
 * `/wasm-inline` (see `wasm-inline.d.ts`) which exposes the options-object
 * API and the `cookieStore`-friendly shape. This file documents the
 * lower-level surface: a single `create(workspaceCrn, accessKey)` factory
 * with no built-in store wiring.
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
 * OAuth-based strategies on wasm (`DeviceSessionStrategy`, `AutoStrategy`) are
 * deferred to a follow-up — see the Layer 3.5 notes in `wasm-analysis.md`.
 */

/** Error codes attached to errors thrown by this package. */
export type AuthErrorCode =
  | 'REQUEST_ERROR'
  | 'ACCESS_DENIED'
  | 'INVALID_GRANT'
  | 'INVALID_CLIENT'
  | 'INVALID_URL'
  | 'INVALID_REGION'
  | 'INVALID_CRN'
  | 'WORKSPACE_MISMATCH'
  | 'INVALID_WORKSPACE_ID'
  | 'MISSING_WORKSPACE_CRN'
  | 'NOT_AUTHENTICATED'
  | 'EXPIRED_TOKEN'
  | 'INVALID_ACCESS_KEY'
  | 'INVALID_TOKEN'
  | 'USAGE_LIMIT_EXCEEDED'
  | 'ORG_NOT_PROVISIONED'
  | 'SERVER_ERROR'
  | 'ALREADY_CONSUMED'
  | 'INTERNAL_ERROR'
  | 'CUSTOM'

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
 * or CI/CD authentication, scoped to a single workspace identified by a
 * CRN. Region is derived from the CRN. Every issued token's `workspace`
 * JWT claim is verified against the CRN; mismatch fails the `getToken()`
 * call with a `WORKSPACE_MISMATCH` error.
 *
 * This is the raw bundler-target binding — consumers wanting the
 * options-object / cookie-store-friendly shape should import from
 * `/wasm-inline` instead.
 */
export declare class AccessKeyStrategy {
  private constructor()
  /**
   * Create a new `AccessKeyStrategy` for the given workspace CRN and
   * access key.
   *
   * The CRN format is `crn:<region>:<workspace-id>` (e.g.
   * `"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"`).
   */
  static create(workspaceCrn: string, accessKey: string): AccessKeyStrategy
  /** Retrieve a valid access token, refreshing or re-authenticating as needed. */
  getToken(): Promise<TokenResult>
  /** Release the underlying wasm resources. */
  free(): void
}

/**
 * Federates a third-party OIDC JWT (Clerk, Supabase, …) into a CipherStash
 * CTS service token. This is the raw bundler-target binding — consumers
 * wanting the options-object / cookie-store-friendly shape should import from
 * `/wasm-inline` instead.
 *
 * `getJwt` / `loadToken` / `saveToken` are JS callbacks returning Promises.
 */
export declare class OidcFederationStrategy {
  private constructor()
  /**
   * Create an `OidcFederationStrategy` for the given workspace CRN. The CRN
   * format is `crn:<region>:<workspace-id>` (e.g.
   * `"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"`).
   *
   * `baseUrl`, when supplied, pins this strategy to a specific CTS host —
   * e.g. a self-hosted CTS or a local mock auth server — overriding region
   * service discovery, scoped to this strategy alone. `cacheCapacity` is how
   * many distinct JWTs keep a CTS token (1024 unless set; `0` caches nothing).
   */
  static create(
    workspaceCrn: string,
    getJwt: () => Promise<string>,
    baseUrl?: string | undefined | null,
    cacheCapacity?: number | undefined | null,
  ): OidcFederationStrategy
  /**
   * Create an `OidcFederationStrategy` backed by external token-store
   * callbacks. Takes the same `workspaceCrn` as {@link create} (region for
   * service discovery, workspace ID for verification) plus `loadToken` /
   * `saveToken` to persist the federated CTS token across requests.
   *
   * `baseUrl` and `cacheCapacity` behave as in {@link create} — an explicit,
   * strategy-scoped CTS host that overrides region service discovery, and the
   * number of JWTs whose token is kept in memory.
   */
  static createWithStore(
    workspaceCrn: string,
    getJwt: () => Promise<string>,
    loadToken: () => Promise<string | null | undefined>,
    saveToken: (json: string) => Promise<void>,
    baseUrl?: string | undefined | null,
    cacheCapacity?: number | undefined | null,
  ): OidcFederationStrategy
  /** Retrieve a valid CTS service token, federating or re-federating as needed. */
  getToken(): Promise<TokenResult>
  /** Release the underlying wasm resources. */
  free(): void
}
