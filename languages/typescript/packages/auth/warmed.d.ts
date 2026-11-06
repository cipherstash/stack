/* tslint:disable */
/* eslint-disable */

/*
 * The warmed `AuthStrategy` shape shared by the `/next` and `/start` entries.
 * Not a public entry of its own: `WarmedAuthStrategy` is re-exported from
 * `@cipherstash/auth/next` and `@cipherstash/auth/start`.
 */

import type { TokenResult } from "./wasm-types.d.ts";
import type { GetTokenResult } from "./wasm-inline.d.ts";

/**
 * An `AuthStrategy` backed by a token an earlier step already federated — it
 * requires no federation, so consumers (incl. protect-ffi) can drive
 * `getToken()` from any context. `getToken()` returns the same `Result` shape
 * as a real strategy (always a `{ data }` success here, since the warmed token
 * is pre-validated), so this stays a drop-in wherever an
 * `OidcFederationStrategy` is consumed.
 *
 * **It does not refresh.** Unlike `OidcFederationStrategy` / `AccessKeyStrategy`,
 * `getToken()` hands back the *same* token every time, so the strategy is valid
 * only until that token's TTL expires — after which downstream CTS/ZeroKMS calls
 * fail with no refresh path. Treat it as request-scoped: a detached callback
 * within the request is fine, but don't cache it across requests — re-read the
 * header (Next.js) or let the middleware run again (TanStack Start) on the next
 * one.
 */
export interface WarmedAuthStrategy {
  readonly requiresFederation: false;
  getToken(): Promise<GetTokenResult>;
  free(): void;
}

/**
 * Wrap an already-federated {@link TokenResult} in a {@link WarmedAuthStrategy}.
 * The adapters call this for you; it is exported for custom wiring that has a
 * `TokenResult` in hand (from `csFederate`, say) and wants the strategy shape.
 */
export declare function warmedStrategy(result: TokenResult): WarmedAuthStrategy;
