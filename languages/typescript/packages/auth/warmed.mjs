/* @ts-self-types="./warmed.d.ts" */

// The warmed `AuthStrategy` shape shared by the `/next` and `/start` adapters:
// a `TokenResult` that some earlier step already federated, wrapped so the
// CipherStash SDKs (and protect-ffi) can drive it like any other strategy.
// Kept out of `next.mjs` so `start.mjs` can build one without importing the
// request-header hand-off that only Next.js needs.

/**
 * Wrap an already-federated token in the no-federation `AuthStrategy` shape.
 *
 * Mirrors a real strategy's Result-returning `getToken()` so the warmed
 * strategy stays a drop-in wherever an `OidcFederationStrategy` /
 * `AccessKeyStrategy` is consumed (e.g. protect-ffi). The token is already
 * validated by the caller, so `getToken()` is always a `{ data }` success — and
 * always the SAME token: this strategy never refreshes, so it is only valid
 * until that token's TTL expires. Hold it no longer than the request that
 * warmed it.
 *
 * @param {import("./wasm-types.d.ts").TokenResult} result
 * @returns {import("./warmed.d.ts").WarmedAuthStrategy}
 */
export function warmedStrategy(result) {
  return {
    requiresFederation: false,
    getToken: async () => ({ data: result }),
    free() {},
  };
}
