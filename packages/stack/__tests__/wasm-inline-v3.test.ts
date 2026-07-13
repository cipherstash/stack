/**
 * `@cipherstash/stack/wasm-inline` is EQL v3 only (#614). This pins the three
 * things that make that true and keep working:
 *
 *   1. The factory always constructs the client with `eqlVersion: 3` — a
 *      v2-mode client cannot resolve the concrete `eql_v3_*` domains and would
 *      fail every encrypt. Only the gated Deno e2e exercises the real wire
 *      format, so this asserts the plumbing the e2e's effect depends on.
 *   2. It still normalises SDK-facing `cast_as` to the EQL-native variant the
 *      WASM client accepts (v3 columns carry `cast_as: 'string'`, not `'text'`).
 *   3. It rejects a v2 table with a clear message rather than pinning v3 wire to
 *      a v2 schema and failing opaquely inside the FFI.
 *
 * It also pins that the v3 authoring surface is re-exported from this entry, so
 * an edge consumer authors v3 schemas from a single import.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
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
// v2 builders come from the native schema entry — used only to prove the WASM
// factory REJECTS a v2 table.
import {
  encryptedColumn,
  encryptedTable as v2EncryptedTable,
} from '../src/schema'
import * as wasm from '../src/wasm-inline'
import { Encryption, encryptedTable, types } from '../src/wasm-inline'

const config = {
  workspaceCrn: 'crn:ap-southeast-2.aws:test-workspace',
  accessKey: 'CSAK.test',
  clientId: 'cid',
  clientKey: 'ckey',
} as const

// biome-ignore lint/suspicious/noExplicitAny: reading the recorded options object
const newClientOpts = () => vi.mocked(wasmNewClient).mock.calls[0][0] as any

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
})

beforeEach(() => {
  vi.clearAllMocks()
})

describe('wasm-inline is EQL v3 only (#614)', () => {
  it('constructs the client with eqlVersion 3', async () => {
    await Encryption({ schemas: [users], config })
    expect(newClientOpts().eqlVersion).toBe(3)
  })

  it('normalises cast_as on the v3 path (SDK "string" → EQL "text")', async () => {
    await Encryption({ schemas: [users], config })
    // `types.TextSearch` carries `cast_as: 'string'`; the WASM client only
    // accepts EQL-native variants, so the factory must map it to `'text'`.
    expect(newClientOpts().encryptConfig.tables.users.email.cast_as).toBe(
      'text',
    )
  })

  it('rejects a v2 table with a clear error, before touching newClient', async () => {
    const v2Users = v2EncryptedTable('users', {
      email: encryptedColumn('email'),
    })
    await expect(
      // A JS caller can bypass the v3-only `schemas` type; the runtime guard
      // must catch it. Cast to satisfy the compile-time type for this test.
      Encryption({
        schemas: [v2Users as unknown as typeof users],
        config,
      }),
    ).rejects.toThrow(/EQL v3 only/)
    expect(vi.mocked(wasmNewClient)).not.toHaveBeenCalled()
  })

  it('re-exports the v3 authoring surface from this entry', () => {
    expect(typeof wasm.encryptedTable).toBe('function')
    expect(typeof wasm.types).toBe('object')
    expect(typeof wasm.types.TextSearch).toBe('function')
    expect(typeof wasm.buildEncryptConfig).toBe('function')
    // The authored table is the v3 builder (carries the v3 `buildColumnKeyMap`
    // marker) — not the v2 one.
    expect(typeof users.buildColumnKeyMap).toBe('function')
    expect(users.email.getEqlType()).toBe('public.eql_v3_text_search')
  })
})
