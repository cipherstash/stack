/**
 * Offline coverage for the WASM `Encryption` factory's `newClient` call shape.
 *
 * protect-ffi 0.25 changed `newClient` from a two-argument form
 * (`newClient(strategy, options)`) to a single options object. 0.31 then
 * converged the wasm and Neon option shapes (protectjs-ffi#143) and began
 * REJECTING unknown keys rather than dropping them (#147), which moved
 * credentials under `clientOpts` and made the SDK `cast_as` vocabulary the
 * thing to send:
 *   `newClient({ authStrategy, encryptConfig, clientOpts, eqlVersion })`.
 *
 * `wasm-inline.ts` performs those migrations, and the only end-to-end exercise
 * of the factory is the Deno e2e (`e2e/wasm/roundtrip.test.ts`), which needs
 * real `CS_*` secrets — so a regression in the call shape passes the normal
 * suite. That is not hypothetical: the top-level `clientId` these tests used to
 * assert on became ``unknown field `clientId` `` under 0.31, failing every
 * client construction, and only the Deno job caught it. These tests mock the
 * WASM bindings and assert the exact argument object handed to
 * `wasmNewClient`.
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

vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ({
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

  it('nests the resolved strategy and puts credentials under clientOpts', async () => {
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
    expect(arg.authStrategy).toEqual({ __mock: 'access-key-strategy' })

    // Under `clientOpts`, NOT at the top level. 0.31 rejects unknown keys, so
    // the old placement fails every construction with `unknown field
    // `clientId``.
    expect(arg.clientOpts).toEqual({ clientId: 'cid', clientKey: 'ckey' })
    expect(arg).not.toHaveProperty('clientId')
    expect(arg).not.toHaveProperty('clientKey')
  })

  it('passes encryptConfig in the SDK vocabulary, untranslated', async () => {
    // `types.TextSearch('email')` carries `cast_as: 'string'`. This entry used
    // to rewrite that to the EQL-native `'text'`, because the wasm build —
    // unlike the Neon one — did not normalise and rejected SDK spellings.
    // 0.31 normalises both entries inside Rust, and keeping the translation
    // would now be wrong rather than redundant: `'double'` and `'jsonb'`, which
    // the old mapping emitted, are in neither the public `CastAs` union nor the
    // canonical one (`'float'` and `'json'`), and unknown values are rejected.
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
    expect(arg.authStrategy).toBe(explicit)
  })
})
