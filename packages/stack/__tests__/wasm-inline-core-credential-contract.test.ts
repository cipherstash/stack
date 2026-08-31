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
 * browser smoke test — `__tests__/browser-export-condition.test.ts` is what
 * holds the packaging half of that, in the default suite where everyone runs
 * it.
 *
 * Nothing else could have caught this, for two different reasons. Every wasm
 * test in stack's DEFAULT suite that constructs a client mocks `newClient`,
 * and `vitest.shared.ts` aliases the whole
 * `@cipherstash/protect-ffi/wasm-inline` specifier to a stub whose `newClient`
 * throws — so none of them reaches the core at all. The suites that DO reach
 * it miss this contract from both sides. The round-trip ones —
 * `integration/wasm/**` here, protect-ffi's own `wasm-round-trip`, the Deno
 * smoke tests in `e2e/wasm/` — hand it a complete, real credential, and a
 * requirement is invisible to a caller that always satisfies it. protect-ffi's
 * `wasm-error-codes` passes no `clientOpts` at all, but every case there fails
 * in config validation, before the credential check, and none supplies an auth
 * strategy. This file is the one that omits the credential WHILE supplying a
 * strategy, so it resolves the REAL module through Node — which the Vite alias
 * does not intercept — and asserts against the actual core.
 *
 * IF THIS TEST FAILS, THAT IS GOOD NEWS — with one exception, named below. It
 * means the core relaxed the requirement and browser support should be
 * re-examined: the `browser` export condition (#805), a live browser smoke
 * test, and browser guidance in `skills/stash-supabase/SKILL.md` are all
 * blocked on this and nothing else. Re-open #804 rather than deleting the
 * assertions. The exception is the `strategy` arm: that option name is
 * deprecated in protect-ffi, and its removal is a rename rather than a
 * relaxation. `STRATEGY_KEYS` below says what to do about it.
 *
 * Runs offline. Every failure asserted here happens during argument
 * deserialisation or key loading, before any ZeroKMS / CTS network call, so no
 * `CS_*` credentials are needed. The credentialed round-trip lives in
 * `e2e/wasm/roundtrip.test.ts` (Deno) — note that it exercises the
 * `accessKey` arm, so the federation arm reasoned about here has no live
 * coverage anywhere.
 *
 * WHERE IT RUNS, and why not with the rest of the suite. Loading the real
 * module means loading `dist/wasm/protect_ffi_inline.js`, which wasm-pack
 * emits and `pnpm install` does not — only the three `.d.ts` beside it are
 * tracked. So this file is excluded from `packages/stack/vitest.config.ts` and
 * collected by `vitest.wasm-core.config.ts` instead, run by `test:wasm-core`
 * from `tests.yml`'s `wasm-e2e-tests` job, the one job that builds it. Left in
 * the default config it does not skip — it fails to COLLECT, which is what it
 * did in `run-tests` (#953). To run it locally, build the WASM output first:
 * `pnpm --filter @cipherstash/protect-ffi run build:wasm` (needs cargo, the
 * wasm32 target and wasm-pack).
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

/**
 * The two option keys the core accepts an auth strategy on, and the reason
 * every assertion below runs twice.
 *
 * `authStrategy` is the SHIPPING path: `src/wasm-inline.ts` builds its call as
 * `wasmNewClient({ authStrategy: strategy, ... })`, so that arm is the one
 * production takes and the one that has to keep passing. `strategy` is the
 * former name — protect-ffi's `NewClientOptions` marks it `@deprecated
 * Renamed to authStrategy`, the core reads it only when `authStrategy` is
 * absent or nullish, and it is documented as going away.
 *
 * When protect-ffi drops it, ONLY the `strategy` arm turns red — the core
 * will not have seen a strategy at all, so the arm fails at auth with `Not
 * authenticated`, or on an unknown field if the key also stops being stripped
 * before serde. Either way it is an alias removal, not a change to the
 * credential contract: delete the `strategy` entry here and the whole arm
 * goes with it. What it must not turn into is a hunt for a core regression,
 * and the assertions must not be consolidated back onto a single key —
 * running both is exactly what keeps the two failures distinguishable.
 */
const STRATEGY_KEYS = [
  { key: 'authStrategy', role: 'the key production passes' },
  { key: 'strategy', role: 'the deprecated alias' },
] as const

for (const { key, role } of STRATEGY_KEYS) {
  describe(`protect-ffi WASM core: credential contract under OIDC federation, on \`opts.${key}\` (${role}) (#804)`, () => {
    it('requires `clientKey` even when an auth strategy is supplied', async () => {
      const { calls, strategy } = federationStrategy()

      await expect(
        newClient({
          clientOpts: { clientId: CLIENT_ID },
          [key]: strategy,
          encryptConfig,
          eqlVersion: 3,
        }),
      ).rejects.toThrow(
        /clientOpts\.clientId and clientOpts\.clientKey are required/,
      )

      // Rejected while the core builds its key provider — the strategy was
      // never INVOKED, so federation cannot substitute for the key. (The core
      // does look at the strategy option before this point, to check it is
      // present and carries a `getToken`; what never happens is the call.)
      //
      // Both credential fields are named in one message: the core does not
      // report which of the pair is missing, it requires both. So this test
      // and the next assert the same string, and each is carried by the field
      // it omits rather than by a distinct error.
      expect(calls.getToken).toBe(0)
    })

    it('requires `clientId` even when an auth strategy is supplied', async () => {
      const { calls, strategy } = federationStrategy()

      await expect(
        newClient({
          clientOpts: { clientKey: HEX_BUT_NOT_KEY_MATERIAL },
          [key]: strategy,
          encryptConfig,
          eqlVersion: 3,
        }),
      ).rejects.toThrow(
        /clientOpts\.clientId and clientOpts\.clientKey are required/,
      )

      expect(calls.getToken).toBe(0)
    })

    it('decodes `clientKey` in two stages — hex, then a key provider', async () => {
      // Two distinct error classes prove two distinct stages. A field that
      // were merely format-checked would have only the first.
      const hexStage = federationStrategy()
      await expect(
        newClient({
          clientOpts: { clientId: CLIENT_ID, clientKey: 'not-hex' },
          [key]: hexStage.strategy,
          encryptConfig,
          eqlVersion: 3,
        }),
      ).rejects.toThrow(/invalid clientKey: expected a hex-encoded key/)

      const providerStage = federationStrategy()
      await expect(
        newClient({
          clientOpts: {
            clientId: CLIENT_ID,
            clientKey: HEX_BUT_NOT_KEY_MATERIAL,
          },
          [key]: providerStage.strategy,
          encryptConfig,
          eqlVersion: 3,
        }),
      ).rejects.toThrow(/Key provider error: Invalid client key/)

      // Neither stage invoked the strategy: key loading strictly precedes
      // auth. The last test in this arm supplies the other half of that
      // claim, by getting past key loading and watching `getToken` fire.
      expect(hexStage.calls.getToken).toBe(0)
      expect(providerStage.calls.getToken).toBe(0)
    })

    it('decodes `clientKey` into cryptographic key material, not an identifier', async () => {
      const { calls, strategy } = federationStrategy()

      // The load-bearing assertion, and the one that separates "the core
      // parses this field" from "the core uses this field as a key". Reaching
      // into the serialised struct, the core reports that `p1` must be a
      // `Permutation` — a keyed permutation, i.e. cryptographic material for
      // the searchable-index schemes. Nothing that merely validated a
      // credential's format would decode a permutation out of it. That is
      // what makes `clientKey` a secret, and therefore what blocks this entry
      // from a browser bundle.
      //
      // This asserts on the core's internal key layout deliberately. If
      // protect-ffi changes it this test fails, and that is the intended
      // prompt to re-read #804 rather than to loosen the assertion.
      await expect(
        newClient({
          clientOpts: { clientId: CLIENT_ID, clientKey: CBOR_KEY_WITH_BAD_P1 },
          [key]: strategy,
          encryptConfig,
          eqlVersion: 3,
        }),
      ).rejects.toThrow(/expected struct Permutation/)

      expect(calls.getToken).toBe(0)
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
          clientOpts: {
            clientId: CLIENT_ID,
            clientKey: WELL_FORMED_KEY_MATERIAL,
          },
          [key]: strategy,
          encryptConfig,
          eqlVersion: 3,
        }),
      ).rejects.toThrow(/Invalid token: JWT must have three segments/)

      expect(calls.getToken).toBe(1)
    })
  })
}

describe('protect-ffi WASM core: the strategy is read before the credentials (#804)', () => {
  it('answers `Not authenticated` when NEITHER key carries a strategy', async () => {
    // Fixes the meaning of every arm above. They all assert "even when an
    // auth strategy is supplied" — which is only worth anything if the core
    // reads the key they supply it on. It does, and this is the control that
    // says so: with the strategy omitted entirely the core answers `Not
    // authenticated` whether or not credentials are present, while
    // credentials omitted WITH a strategy gives the credential error — so the
    // strategy is seen first. Verified by probing all three combinations
    // against the real core, not inferred from the source.
    //
    // This is also the drift guard, and it now guards a pair. `authStrategy`
    // is the field the core reads first and the field production passes;
    // `strategy` is the fallback it reads only when `authStrategy` is absent.
    // If protect-ffi renamed or removed either, that arm would be handing the
    // core nothing and quietly exercising THIS path instead — it would fail
    // rather than pass silently, because `Not authenticated` matches none of
    // its regexes, and this test names the string it would fail with.
    await expect(
      newClient({
        clientOpts: {
          clientId: CLIENT_ID,
          clientKey: HEX_BUT_NOT_KEY_MATERIAL,
        },
        encryptConfig,
        eqlVersion: 3,
      }),
    ).rejects.toThrow(/Not authenticated/)
  })
})

// The packaging consequence of everything above — that neither
// `@cipherstash/stack` nor `@cipherstash/stack-supabase` declares a `browser`
// export condition — used to be asserted here. It has moved to
// `__tests__/browser-export-condition.test.ts` (and its sibling in
// `packages/stack-supabase/__tests__/`), because it only reads a manifest:
// hosted in this file it inherited this file's exclusion from the default
// config and so ran in one CI job and in nobody's local test run. Anyone
// following #804 wants both files.
