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
 * Nothing else in the suite could have caught this: every wasm test that
 * constructs a client mocks `newClient`, and `vitest.shared.ts` aliases the
 * whole `@cipherstash/protect-ffi/wasm-inline` specifier to a stub whose
 * `newClient` throws. So this file resolves the REAL module through Node —
 * which the Vite alias does not intercept — and asserts against the actual
 * core.
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
 * `e2e/wasm/roundtrip.test.ts` (Deno) — note that it exercises the
 * `accessKey` arm, so the federation arm reasoned about here has no live
 * coverage anywhere.
 */

import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
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

// Synthetic key material that is STRUCTURALLY complete — enough to clear the
// key provider entirely, which is what makes the positive control below
// possible. Derived from the core's own error messages, not from any real
// credential: the struct is `{ p1, p2_from, p2_to, p3 }`, each a
// `Permutation { permutation: [...] }`. Here every permutation is empty, so
// this is well-formed but cryptographically worthless — it exists only to get
// past key loading and observe what happens next.
const WELL_FORMED_KEY_MATERIAL =
  'a4627031a16b7065726d75746174696f6e80' + // p1:      { permutation: [] }
  '6770325f66726f6da16b7065726d75746174696f6e80' + // p2_from: { permutation: [] }
  '6570325f746fa16b7065726d75746174696f6e80' + // p2_to:   { permutation: [] }
  '627033a16b7065726d75746174696f6e80' // p3:      { permutation: [] }

/**
 * An `OidcFederationStrategy`-shaped stand-in. The core duck-types the
 * strategy — it checks `getToken` is a function and calls it — so a plain
 * object is a faithful stand-in, and it records whether the call happened,
 * which is the point of these tests.
 *
 * The token is deliberately not a well-formed JWT. That guarantees the one
 * test that does reach auth stops at local token parsing, so this file stays
 * offline no matter how far into the pipeline a future core gets.
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
    // never INVOKED, so federation cannot substitute for the key. (The core
    // does look at `opts.strategy` before this point, to check it is present
    // and carries a `getToken`; what never happens is the call.)
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

    // Neither stage invoked the strategy: key loading strictly precedes auth.
    // The last test in this file supplies the other half of that claim, by
    // getting past key loading and watching `getToken` fire.
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

  it('reads the strategy off `opts.strategy`, before it deserialises the credentials', async () => {
    // Fixes the meaning of every test above. They all assert "even when an
    // auth strategy is supplied" — which is only worth anything if the core
    // reads the field they supply it on. It does: omitting `strategy`
    // entirely beats `missing field \`clientKey\`` to the punch, so the
    // strategy is seen before the credentials are even deserialised.
    //
    // This is also the drift guard. If protect-ffi renamed the option, the
    // tests above would be handing the core nothing and quietly testing the
    // no-strategy path instead. They would fail rather than pass silently
    // (`opts.strategy is required` matches none of their regexes), and this
    // test names the reason.
    await expect(
      newClient({
        clientId: CLIENT_ID,
        clientKey: HEX_BUT_NOT_KEY_MATERIAL,
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/opts\.strategy is required/)
  })

  it('invokes `getToken` only after key loading succeeds', async () => {
    const { calls, strategy } = federationStrategy()

    // The positive control for every `toBe(0)` above. Without it those
    // assertions could not tell "auth comes after key loading" apart from
    // "auth never happens during `newClient` at all" — a counter that is
    // never incremented reads as 0 either way.
    //
    // Structurally complete key material clears the key provider, and the
    // core then calls `getToken` exactly once, failing on the deliberately
    // malformed token this stand-in returns. So: auth IS reached during
    // construction, it is reached only after the key is loaded, and the
    // counter these tests rely on is live.
    await expect(
      newClient({
        clientId: CLIENT_ID,
        clientKey: WELL_FORMED_KEY_MATERIAL,
        strategy,
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/Invalid token: JWT must have three segments/)

    expect(calls.getToken).toBe(1)
  })
})

describe('@cipherstash/stack declares no browser build (#804)', () => {
  it('has no `browser` export condition on any subpath', () => {
    // The consequence of everything above, and the one part of it a reader
    // can act on by accident. `src/wasm-inline.ts` tells callers there is no
    // `browser` condition and explains why; nothing enforced that, so adding
    // one to fix a bundler complaint would ship a workspace secret to the
    // browser and leave the doc silently wrong.
    //
    // Same rule as the rest of this file: if the core stops requiring
    // `clientKey`, come back through #804 — don't just delete this.
    const packageJson = JSON.parse(
      readFileSync(
        path.resolve(fileURLToPath(import.meta.url), '../../package.json'),
        'utf8',
      ),
    ) as { browser?: unknown; exports: Record<string, unknown> }

    expect(packageJson.browser).toBeUndefined()
    expect(JSON.stringify(packageJson.exports)).not.toContain('"browser"')
  })
})
