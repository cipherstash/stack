/**
 * Contract test: the WASM core requires `clientId` AND `clientKey` on EVERY
 * auth path — including OIDC federation, the arm that exists so a caller never
 * handles a workspace secret.
 *
 * Why this file exists (#804). `WasmClientConfig` puts `clientId` / `clientKey`
 * on the base of its intersection, so they are required even when
 * `config.authStrategy` is an `OidcFederationStrategy`. That looked like it
 * might be a leftover from the access-key path that the type over-declares — in
 * which case a browser could construct a client from a federated JWT alone. It
 * is not. The requirement is real, it comes from the Rust core, and `clientKey`
 * is a workspace secret, so `@cipherstash/stack/wasm-inline` is not
 * browser-safe. That is why there is no `browser` export condition and no
 * browser smoke test.
 *
 * Nothing else in the suite could have caught this: every other wasm test
 * mocks `newClient`, and `vitest.shared.ts` aliases the whole
 * `@cipherstash/protect-ffi/wasm-inline` specifier to a stub that throws. So
 * this file resolves the REAL module through Node — which the Vite alias does
 * not intercept — and asserts against the actual core.
 *
 * IF THIS TEST FAILS, THAT IS GOOD NEWS. It means the core relaxed the
 * requirement and browser support should be re-examined: the `browser` export
 * condition (#805), a live browser smoke test, and browser guidance in
 * `skills/stash-supabase/SKILL.md` are all blocked on this and nothing else.
 * Re-open #804 rather than deleting the assertions.
 *
 * Runs offline. Every failure asserted here happens during argument
 * deserialisation or key loading, before any ZeroKMS / CTS network call, so no
 * `CS_*` credentials are needed. The credentialed round-trip lives in
 * `e2e/wasm/roundtrip.test.ts` (Deno).
 */

import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import { describe, expect, it } from 'vitest'

// Node's resolver, not Vite's — this is what dodges the stub alias. The
// specifier is then imported as an absolute `file://` URL, which matches no
// alias key, so the real inlined-WASM build is what gets loaded.
const nodeRequire = createRequire(import.meta.url)
const realWasmEntry = pathToFileURL(
  nodeRequire.resolve('@cipherstash/protect-ffi/wasm-inline'),
).href

const { newClient } = (await import(realWasmEntry)) as {
  newClient: (opts: unknown) => Promise<unknown>
}

// The smallest config the core accepts. `v: 1` is the encrypt-config envelope
// version, unrelated to EQL v2/v3 — `eqlVersion` below selects the wire format.
const encryptConfig = {
  v: 1,
  tables: { users: { email: { cast_as: 'text', indexes: {} } } },
}

const CLIENT_ID = '00000000-0000-4000-8000-000000000000'

// Valid hex, but NOT a well-formed client key — it decodes to bytes that are
// not a serialised key. Enough to clear hex decoding and reach the key
// provider, which is all the tests below need; none of them requires real key
// material, and none should be read as exercising one.
const HEX_BUT_NOT_KEY_MATERIAL = 'a'.repeat(64)

// A real `CS_CLIENT_KEY` is hex of a CBOR-serialised key struct (see
// `stash env`, which hex-encodes what ZeroKMS returns). This is the smallest
// input that reaches *into* that struct: CBOR for `{ "p1": h'' }`, which gets
// past the outer map and fails on `p1`'s type. What the core says it wanted
// there is the point of the third test.
const CBOR_KEY_WITH_BAD_P1 = 'a1627031' + '40'

/**
 * An `OidcFederationStrategy`-shaped stand-in. The core calls `getToken()` on
 * whatever it is handed, so a plain object is a faithful stand-in — and it
 * records whether the call happened, which is the point of these tests.
 */
function federationStrategy() {
  const calls = { getToken: 0 }
  return {
    calls,
    strategy: {
      getToken: async () => {
        calls.getToken++
        return { data: { token: 'not-a-real-token' } }
      },
    },
  }
}

describe('protect-ffi WASM core: credential contract under OIDC federation (#804)', () => {
  it('requires `clientKey` even when an auth strategy is supplied', async () => {
    const { calls, strategy } = federationStrategy()

    await expect(
      newClient({
        clientId: CLIENT_ID,
        strategy,
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/missing field `clientKey`/)

    // Rejected during deserialisation of the options struct — the strategy was
    // never consulted, so federation cannot substitute for the key.
    expect(calls.getToken).toBe(0)
  })

  it('requires `clientId` even when an auth strategy is supplied', async () => {
    const { calls, strategy } = federationStrategy()

    await expect(
      newClient({
        clientKey: HEX_BUT_NOT_KEY_MATERIAL,
        strategy,
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/missing field `clientId`/)

    expect(calls.getToken).toBe(0)
  })

  it('decodes `clientKey` in two stages — hex, then a key provider', async () => {
    // Two distinct error classes prove two distinct stages. A field that were
    // merely format-checked would have only the first.
    const hexStage = federationStrategy()
    await expect(
      newClient({
        clientId: CLIENT_ID,
        clientKey: 'not-hex',
        strategy: hexStage.strategy,
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/invalid clientKey: invalid hex/)

    const providerStage = federationStrategy()
    await expect(
      newClient({
        clientId: CLIENT_ID,
        clientKey: HEX_BUT_NOT_KEY_MATERIAL,
        strategy: providerStage.strategy,
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/Key provider error: Invalid client key/)

    // Neither stage consulted the strategy: key loading strictly precedes auth.
    expect(hexStage.calls.getToken).toBe(0)
    expect(providerStage.calls.getToken).toBe(0)
  })

  it('decodes `clientKey` into cryptographic key material, not an identifier', async () => {
    const { calls, strategy } = federationStrategy()

    // The load-bearing assertion, and the one that separates "the core parses
    // this field" from "the core uses this field as a key". Reaching into the
    // serialised struct, the core reports that `p1` must be a `Permutation` —
    // a keyed permutation, i.e. cryptographic material for the searchable-index
    // schemes. Nothing that merely validated a credential's format would decode
    // a permutation out of it. That is what makes `clientKey` a secret, and
    // therefore what blocks this entry from a browser bundle.
    //
    // This asserts on the core's internal key layout deliberately. If protect-ffi
    // changes it this test fails, and that is the intended prompt to re-read
    // #804 rather than to loosen the assertion.
    await expect(
      newClient({
        clientId: CLIENT_ID,
        clientKey: CBOR_KEY_WITH_BAD_P1,
        strategy,
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/expected struct Permutation/)

    expect(calls.getToken).toBe(0)
  })
})
