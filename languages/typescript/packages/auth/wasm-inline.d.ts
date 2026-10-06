/* tslint:disable */
/* eslint-disable */

/*
 * Public TS surface for the `/wasm-inline` entry — the slick wrapper around
 * the raw wasm-bindgen-generated bindings. Consumers see this; the raw
 * `createWithStore(crn, key, loadFn, saveFn)` shape stays internal.
 *
 * Every fallible operation returns a `@byteslice/result` `Result<T, AuthFailure>`
 * (`{ data }` on success, `{ failure }` on error) assembled by the wrapper in
 * `wasm-inline.mjs` from the structured error the wasm layer attaches — so
 * consumers write `if (result.failure) …` and never `try/catch`. (The lower-
 * level `/wasm` entry still throws; see `wasm-types.d.ts`.)
 */

import type { Result } from "@byteslice/result";

export type { TokenResult } from "./wasm-types.d.ts";

/** Fields present on every {@link AuthFailure}. */
interface FailureBase {
  /** The live `Error` from the wasm boundary, with `.message`/`.code`. */
  error: Error;
  /** Actionable diagnostic guidance, when the error carries it. */
  help?: string;
  /** A URL with more detail, when the error carries it. */
  url?: string;
}

/**
 * A domain failure returned in the `failure` arm of a `Result`. Discriminated
 * by `type`; narrow to access per-variant payload (e.g. `WORKSPACE_MISMATCH`'s
 * `expected`/`actual`). This is the full code set; the wasm strategies emit a
 * subset (no device-flow or filesystem-store codes).
 */
export type AuthFailure =
  | (FailureBase & { type: "REQUEST_ERROR" })
  | (FailureBase & { type: "ACCESS_DENIED" })
  | (FailureBase & { type: "EXPIRED_TOKEN" })
  | (FailureBase & { type: "INVALID_GRANT" })
  | (FailureBase & { type: "INVALID_CLIENT" })
  | (FailureBase & { type: "INVALID_URL" })
  | (FailureBase & { type: "INVALID_REGION" })
  | (FailureBase & { type: "INVALID_TOKEN" })
  | (FailureBase & { type: "USAGE_LIMIT_EXCEEDED" })
  | (FailureBase & { type: "ORG_NOT_PROVISIONED" })
  | (FailureBase & { type: "SERVER_ERROR" })
  | (FailureBase & { type: "NOT_AUTHENTICATED" })
  | (FailureBase & { type: "MISSING_WORKSPACE_CRN" })
  | (FailureBase & { type: "INVALID_ACCESS_KEY" })
  | (FailureBase & { type: "INVALID_CRN" })
  | (FailureBase & { type: "WORKSPACE_MISMATCH"; expected: string; actual: string })
  | (FailureBase & { type: "INVALID_WORKSPACE_ID" })
  | (FailureBase & { type: "ALREADY_CONSUMED" })
  | (FailureBase & { type: "INTERNAL_ERROR" })
  | (FailureBase & { type: "CUSTOM" })
  | (FailureBase & { type: "STORE_ERROR" });

/** The machine-readable discriminant carried by every {@link AuthFailure}. */
export type AuthErrorCode = AuthFailure["type"];

/** The resolved value of a `getToken()` call. */
export type GetTokenResult = Result<
  import("./wasm-types.d.ts").TokenResult,
  AuthFailure
>;

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
   * Capability flag — `false` for this ambient strategy: the credential is a
   * static value, so `getToken()` self-refreshes and can be driven from any
   * context. (Contrast {@link OidcFederationStrategy.requiresFederation}.)
   */
  readonly requiresFederation: false;
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
  ): Result<AccessKeyStrategy, AuthFailure>;
  /** Retrieve a valid access token, refreshing or re-authenticating as needed. */
  getToken(): Promise<GetTokenResult>;
  /** Release the underlying wasm resources. */
  free(): void;
}

/**
 * Supplies the third-party OIDC JWT of the user the current request is for.
 * Called on every `getToken()`; one CTS token is cached per distinct JWT, so
 * return a live token each time (e.g. `() => clerk.session.getToken()`), never
 * one captured at startup.
 */
export type OidcProvider = () => string | Promise<string>;

/** Options accepted by {@link OidcFederationStrategy.create}. */
export interface OidcFederationStrategyOptions {
  /**
   * External persistence for the federated CTS token — see
   * {@link AccessKeyStrategyOptions.store}.
   */
  store?: TokenStore;
  /**
   * Pin this strategy to a specific CTS host — e.g. a self-hosted CTS or a
   * local mock auth server — overriding region service discovery. Scoped to
   * this strategy alone. In wasm there is no `CS_CTS_HOST` env fallback, so
   * this is the only way to target a host other than the region-discovered one.
   */
  baseUrl?: string;
}

/**
 * An auth strategy that federates a third-party OIDC JWT (Clerk, Supabase, …)
 * into a CipherStash CTS service token via `/api/authorise`.
 */
export declare class OidcFederationStrategy {
  private constructor();
  /**
   * Capability flag — `true` for this federated strategy: the third-party JWT
   * and token cache are request-scoped, so federation must happen in scope.
   * Consumers should read a warmed token (`@cipherstash/auth/next`) rather than
   * drive `getToken()` from a detached context.
   */
  readonly requiresFederation: true;
  /**
   * Create an `OidcFederationStrategy` for the given workspace CRN.
   *
   * The CRN format is `crn:<region>:<workspace-id>` (e.g.
   * `"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"`). Region is parsed from the
   * CRN and used for service discovery; the workspace ID is used to verify
   * every federated token belongs to the right workspace.
   *
   * `getJwt` must return the current third-party OIDC JWT (it is re-invoked
   * on every re-federation). Pass `options.store` to back the strategy with a
   * persistent cache — see {@link TokenStore}.
   */
  static create(
    workspaceCrn: string,
    getJwt: OidcProvider,
    options?: OidcFederationStrategyOptions,
  ): Result<OidcFederationStrategy, AuthFailure>;
  /** Retrieve a valid CTS service token, federating or re-federating as needed. */
  getToken(): Promise<GetTokenResult>;
  /** Release the underlying wasm resources. */
  free(): void;
}
