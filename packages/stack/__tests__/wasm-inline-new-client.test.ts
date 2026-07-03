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
    create: vi.fn(() => ({ __mock: 'access-key-strategy' })),
  },
  OidcFederationStrategy: class {},
}))

vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ({
  newClient: vi.fn(async () => ({ __mock: 'wasm-client' })),
  encrypt: vi.fn(),
  decrypt: vi.fn(),
  isEncrypted: vi.fn(),
}))

import { newClient as wasmNewClient } from '@cipherstash/protect-ffi/wasm-inline'
import { Encryption, encryptedColumn, encryptedTable } from '../src/wasm-inline'

const CRN = 'crn:ap-southeast-2.aws:test-workspace'

const users = encryptedTable('users', {
  email: encryptedColumn('email'),
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

  it('nests the resolved strategy and forwards clientId / clientKey', async () => {
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
    expect(arg.strategy).toEqual({ __mock: 'access-key-strategy' })
    expect(arg.clientId).toBe('cid')
    expect(arg.clientKey).toBe('ckey')
  })

  it('passes a cast_as-normalised encryptConfig (SDK "string" → EQL "text")', async () => {
    // `encryptedColumn('email')` defaults to `cast_as: 'string'`; the WASM
    // client only accepts EQL-native variants, so the factory must run the
    // config through `normalizeCastAs` before handing it to `newClient`.
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
    expect(arg.encryptConfig.tables.users.email.cast_as).toBe('text')
  })

  it('uses an explicit config.strategy verbatim on the strategy path', async () => {
    const explicit = { getToken: vi.fn() }
    await Encryption({
      schemas: [users],
      // biome-ignore lint/suspicious/noExplicitAny: exercise the strategy arm of the config union
      config: { strategy: explicit, clientId: 'cid', clientKey: 'ckey' } as any,
    })

    // biome-ignore lint/suspicious/noExplicitAny: reading the recorded single options object
    const arg = vi.mocked(wasmNewClient).mock.calls[0][0] as any
    expect(arg.strategy).toBe(explicit)
  })
})
