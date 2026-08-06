// Contract coverage for the `OidcFederation` auth strategy.
//
// `stack-auth` introduced an `OidcFederationStrategy` that federates a
// third-party OIDC JWT (Clerk, Supabase, …) into a CipherStash CTS service
// token via `POST /api/authorise`. It is surfaced to JS by `@cipherstash/auth`
// (>= 0.39.0) on both the node and `wasm-inline` entries.
//
// From protect-ffi's perspective it is just another `opts.strategy`: the
// native boundary duck-types on the
// `AuthStrategy = { getToken: () => Promise<{ token: string }> }` contract
// (see `src/index.cts`) and never branches on the concrete strategy type. The
// OIDC-specific thing worth asserting here is that the *real published*
// strategy satisfies that contract — which this test does hermetically, with
// no credentials and no network.
//
// The strategy-agnostic FFI behaviours are already covered elsewhere and not
// duplicated here:
//
//   - That a strategy threads through `newClient` and a rejected `getToken`
//     propagates to the caller: `js-strategy.test.ts`.
//   - The FFI ⇄ wasm-strategy ⇄ ZeroKMS encrypt/decrypt path: via
//     `AccessKeyStrategy` in `wasm-round-trip.test.ts` / `js-strategy.test.ts`.
//     (The strategy *type* is irrelevant to the FFI, which only calls
//     `getToken`.)
//
// # Why there is no live end-to-end round-trip here
//
// A real federation round-trip (third-party JWT → CTS token → encrypt/decrypt)
// is deliberately *not* tested in this repo:
//
//   - The OIDC-specific part (`getJwt` → `/api/authorise` → CTS token) lives
//     entirely inside `stack-auth`, which tests it hermetically with its own
//     `MockAuthServer` + a base-URL override. That override is `test-utils`-
//     gated and not exposed on the published consumer API, so it cannot be
//     reproduced here.
//   - A live round-trip would need a *fresh* third-party OIDC JWT per run (they
//     expire in minutes), so it can't be driven from a static CI secret without
//     real IdP infrastructure — and gating it on an env var that CI never sets
//     would make it permanently skipped: green but inert.

import { OidcFederationStrategy } from '@cipherstash/auth/wasm-inline'
import { describe, expect, test } from 'vitest'

import type { AuthStrategy } from '@cipherstash/protect-ffi'

describe('OidcFederation strategy contract', () => {
  test('the published strategy constructs and exposes getToken', () => {
    // Exercises the real `@cipherstash/auth` factory + signature, not a stand-in.
    // `OidcFederationStrategy.create(region, workspaceId, getJwt)` takes the
    // region (`<region>.<provider>`) and workspace id as separate args. Both are
    // arbitrary here — `.create` does no I/O, so this stays offline; the
    // federation call would only happen on `getToken()`.
    const strategy = OidcFederationStrategy.create(
      'ap-southeast-2.aws',
      'ZVATKW3VHMFG27DY',
      () => 'third-party.oidc.jwt',
    )

    // Compile-time: the wasm strategy is structurally assignable to the FFI's
    // `AuthStrategy`. Runtime: `getToken` — the only member the FFI calls — is
    // callable on that contract-typed handle.
    const asStrategy: AuthStrategy = strategy
    expect(typeof asStrategy.getToken).toBe('function')
  })
})
