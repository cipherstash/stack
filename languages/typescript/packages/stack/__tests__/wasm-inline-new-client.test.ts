/**
 * Offline coverage for the WASM `Encryption` factory's `newClient` call shape.
 *
 * protect-ffi 0.25 changed `newClient` from a two-argument form
 * (`newClient(strategy, options)`) to a single options object with the
 * strategy nested under `strategy`:
 *   `newClient({ strategy, encryptConfig, clientId, clientKey })`.
 *
 * `wasm-inline.ts` performs that migration, but the only end-to-end exercise
 * of the factory is the Deno e2e (`e2e/wasm/roundtrip.test.ts`), which skips
 * without real `CS_*` secrets — so a regression in the call shape (e.g.
 * reverting to the two-arg form, dropping `clientId`/`clientKey`, or failing to
 * normalise `cast_as`) would pass the normal suite. These tests mock the WASM
 * bindings and assert the exact argument object handed to `wasmNewClient`.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    // `@cipherstash/auth` `0.41` `create` returns a `Result<Strategy, AuthFailure>`
    // (`{ data }` on success) — `resolveStrategy` unwraps `.data`.
    create: vi.fn(() => ({ data: { __mock: 'access-key-strategy' } })),
  },
  OidcFederationStrategy: class {},
}))

vi.mock('@cipherstash/protect-ffi/wasm-inline', async (importOriginal) => ({
  // Partial, not total: `readErrorCode` validates `failure.code` against the
  // closed `ProtectErrorCode` set with the real `isProtectErrorCode`, and a
  // hand-written stand-in would let a wrong answer through.
  ...(await importOriginal<
    typeof import('@cipherstash/protect-ffi/wasm-inline')
  >()),
  newClient: vi.fn(async () => ({ __mock: 'wasm-client' })),
  encrypt: vi.fn(),
  decrypt: vi.fn(),
  isEncrypted: vi.fn(),
}))

import { newClient as wasmNewClient } from '@cipherstash/protect-ffi/wasm-inline'
import { Encryption, encryptedTable, types } from '../src/wasm-inline'

const CRN = 'crn:ap-southeast-2.aws:test-workspace'

// The WASM entry is EQL v3 — author with the `types` DSL re-exported from it.
const users = encryptedTable('users', {
  email: types.TextSearch('email'),
})

beforeEach(() => {
  vi.clearAllMocks()
})

describe('wasm-inline Encryption → newClient (protect-ffi 0.25 single-object form)', () => {
  it('calls newClient with a single options object, not the 0.24 two-arg form', async () => {
    await Encryption({
      schemas: [users],
      config: {
        workspaceCrn: CRN,
        accessKey: 'CSAK.test',
        clientId: 'cid',
        clientKey: 'ckey',
      },
    })

    expect(vi.mocked(wasmNewClient)).toHaveBeenCalledTimes(1)
    // The 0.24 form passed the strategy as a separate first positional arg.
    // The 0.25 form is a single object — guard against regressing to two args.
    const call = vi.mocked(wasmNewClient).mock.calls[0]
    expect(call).toHaveLength(1)
  })

  it('nests the resolved strategy and credentials under their 0.31 keys', async () => {
    await Encryption({
      schemas: [users],
      config: {
        workspaceCrn: CRN,
        accessKey: 'CSAK.test',
        clientId: 'cid',
        clientKey: 'ckey',
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: reading the recorded single options object
    const arg = vi.mocked(wasmNewClient).mock.calls[0][0] as any

    // protect-ffi 0.31 moved the credentials into `clientOpts`, where the Neon
    // entry has always had them, and renamed `strategy` to `authStrategy`.
    // Credentials left at the top level are now REJECTED, so that half fails
    // loudly — but a `keyset` left there is silently ignored and the client
    // binds to the default keyset, encrypting under the wrong keys. This
    // config forwards no keyset; if one is added it goes inside `clientOpts`,
    // and this test is what should catch it landing anywhere else.
    expect(arg.authStrategy).toEqual({ __mock: 'access-key-strategy' })
    expect(arg.clientOpts).toEqual({ clientId: 'cid', clientKey: 'ckey' })
    expect(arg.clientId).toBeUndefined()
    expect(arg.clientKey).toBeUndefined()
    expect(arg.strategy).toBeUndefined()
  })

  it('forwards encryptConfig unnormalised, letting the FFI canonicalise', async () => {
    // `types.TextSearch('email')` carries `cast_as: 'string'`. Under 0.30 the
    // WASM binding accepted EQL-native variants only, so the factory ran the
    // config through `normalizeCastAs` first. 0.31 normalizes at the Rust
    // deserialization boundary on both bindings — verified against the 0.31
    // wasm build, where `'string'` and `'text'` both get past config parsing to
    // authentication — so the SDK spelling now goes through untouched.
    await Encryption({
      schemas: [users],
      config: {
        workspaceCrn: CRN,
        accessKey: 'CSAK.test',
        clientId: 'cid',
        clientKey: 'ckey',
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: navigating the recorded encryptConfig
    const arg = vi.mocked(wasmNewClient).mock.calls[0][0] as any
    expect(arg.encryptConfig).toBeDefined()
    expect(arg.encryptConfig.tables.users.email.cast_as).toBe('string')
  })

  it('uses an explicit config.authStrategy verbatim on the strategy path', async () => {
    const explicit = { getToken: vi.fn() }
    await Encryption({
      schemas: [users],
      config: {
        authStrategy: explicit,
        clientId: 'cid',
        clientKey: 'ckey',
        // biome-ignore lint/suspicious/noExplicitAny: exercise the authStrategy arm of the config union
      } as any,
    })

    // biome-ignore lint/suspicious/noExplicitAny: reading the recorded single options object
    const arg = vi.mocked(wasmNewClient).mock.calls[0][0] as any
    // `authStrategy` since 0.31. `strategy` still works there as a deprecated
    // alias, but this passes the resolved strategy under the current name so
    // the call does not depend on a field slated for removal.
    expect(arg.authStrategy).toBe(explicit)
    expect(arg.strategy).toBeUndefined()
  })
})
