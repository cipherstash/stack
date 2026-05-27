/* tslint:disable */
/* eslint-disable */

/*
 * Public TS surface for the `/wasm-inline` entry — the slick wrapper around
 * the raw wasm-bindgen-generated bindings. Consumers see this; the raw
 * `createWithStore(crn, key, loadFn, saveFn)` shape stays internal.
 *
 * `AuthErrorCode`, `AuthError`, and `TokenResult` are shared with the
 * lower-level `/wasm` entry via `wasm-types.d.ts` — re-exported here so
 * importers only need one TS module reference.
 */

export type { AuthErrorCode, AuthError, TokenResult } from "./wasm-types.d.ts";

/**
 * Pluggable persistent cache for service tokens. Pair with the
 * `cookieStore` helper from `@cipherstash/auth/cookies` to back the
 * strategy with HTTP-only cookies in Edge / Workers / Bun / Deno / Node
 * App Router runtimes — or hand-roll your own for KV, Redis, etc.
 *
 * Both methods are best-effort. `load` returning `null` / `undefined` is
 * treated as "cache miss" and falls through to fresh authentication.
 * Rejections in either callback are logged via `console.warn` and
 * otherwise ignored.
 */
export interface TokenStore {
  load(): Promise<string | null | undefined>;
  save(json: string): Promise<void>;
}

/** Options accepted by {@link AccessKeyStrategy.create}. */
export interface AccessKeyStrategyOptions {
  /**
   * External persistence. Consulted on cold start before issuing any HTTP
   * request, and written to after every successful refresh / initial auth.
   * Use to share a service-token cache across short-lived strategy
   * instances (one per Edge invocation, one per worker, etc).
   */
  store?: TokenStore;
}

/**
 * An auth strategy that uses a static access key for service-to-service
 * or CI/CD authentication, scoped to a single workspace identified by a
 * CRN. The region is derived from the CRN, so there's no separate
 * `region` argument and no chance of the strategy operating against a
 * region the caller didn't expect.
 *
 * Every issued token's `workspace` JWT claim is verified against the
 * CRN's workspace ID. A mismatch fails the `getToken()` call with an
 * `AuthError` whose `code` is `"WORKSPACE_MISMATCH"` — the strategy
 * never silently lets a multi-workspace access key operate on the
 * wrong workspace.
 */
export declare class AccessKeyStrategy {
  private constructor();
  /**
   * Create a new `AccessKeyStrategy` for the given workspace CRN and
   * access key.
   *
   * The CRN format is `crn:<region>:<workspace-id>` (e.g.
   * `"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"`). Region is parsed from
   * the CRN and used for service discovery; the workspace ID is used
   * to verify every issued token belongs to the right workspace.
   *
   * Pass `options.store` to back the strategy with a persistent cache —
   * see {@link TokenStore} and the
   * {@link https://www.npmjs.com/package/@cipherstash/auth | `@cipherstash/auth/cookies`}
   * helper.
   */
  static create(
    workspaceCrn: string,
    accessKey: string,
    options?: AccessKeyStrategyOptions,
  ): AccessKeyStrategy;
  /** Retrieve a valid access token, refreshing or re-authenticating as needed. */
  getToken(): Promise<import("./wasm-types.d.ts").TokenResult>;
  /** Release the underlying wasm resources. */
  free(): void;
}
