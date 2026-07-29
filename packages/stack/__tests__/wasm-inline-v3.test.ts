/**
 * `@cipherstash/stack/wasm-inline` is EQL v3 only (#614). This pins the things
 * that make that true and keep working:
 *
 *   1. The factory always constructs the client with `eqlVersion: 3` — a
 *      v2-mode client cannot resolve the concrete `eql_v3_*` domains and would
 *      fail every encrypt. Only the gated Deno e2e exercises the real wire
 *      format, so this asserts the plumbing the e2e's effect depends on.
 *   2. It still normalises SDK-facing `cast_as` to the EQL-native variant the
 *      WASM client accepts (v3 columns carry `cast_as: 'string'`, not `'text'`).
 *   3. It rejects a v2 table with a clear message rather than pinning v3 wire to
 *      a v2 schema and failing opaquely inside the FFI.
 *   4. That message does not refer the reader on to the native entry for v2
 *      authoring, and `config.eqlVersion` is rejected here exactly as the native
 *      entry rejects it (#815). #815 exists because the two entries disagreed
 *      about v2; a guard on only one of them would reopen it.
 *   5. The runtime `!schemas.length` guard actually runs — it was previously
 *      pinned only by a `@ts-expect-error` type test, which never executes.
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
    const v2Users = {
      tableName: 'users',
      build: () => ({ tableName: 'users', columns: {} }),
    }
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

  // #815: the message used to close with "(EQL v2 is available on the native
  // `@cipherstash/stack` entry.)" — false since the native entry started
  // rejecting v2 authoring too. A customer following it hit a second rejection.
  // Pin the substantive claim (v2 authoring is gone everywhere, decrypt
  // survives), not the `EQL v3 only` prefix that the test above already covers
  // and that a stale referral would still satisfy.
  it('does not send the reader to the native entry for v2 authoring', async () => {
    const v2Users = {
      tableName: 'users',
      build: () => ({ tableName: 'users', columns: {} }),
    }
    const err = await Encryption({
      schemas: [v2Users as unknown as typeof users],
      config,
    }).catch((e: unknown) => e)

    expect(err).toBeInstanceOf(Error)
    const message = (err as Error).message
    // No referral to another entry as a place v2 authoring still works.
    expect(message).not.toMatch(/EQL v2 is available/)
    expect(message).not.toMatch(/native `?@cipherstash\/stack`? entry/)
    // It must say the removal is repo-wide, and that reads still work — the two
    // facts that stop a customer hunting for a v2-capable entry that is gone.
    expect(message).toMatch(
      /EQL v2 authoring has been removed from every entry/,
    )
    expect(message).toMatch(/decrypt/)
  })

  // #815: native throws on the PRESENCE of `config.eqlVersion`
  // (`Object.hasOwn`, packages/stack/src/encryption/index.ts). The WASM factory
  // had no equivalent, so a JS/JSON caller carrying `eqlVersion: 2` got a hard
  // error on one entry and silence on the other — the exact entry-disagreement
  // #815 exists to close.
  it.each([
    2, 3,
  ])('rejects config.eqlVersion (%i) the way the native entry does', async (eqlVersion) => {
    await expect(
      Encryption({
        schemas: [users],
        // A JS caller can carry this key even though the type omits it.
        config: { ...config, eqlVersion } as unknown as typeof config,
      }),
    ).rejects.toThrow(/`config\.eqlVersion` has been removed/)
    expect(vi.mocked(wasmNewClient)).not.toHaveBeenCalled()
  })

  // `eqlVersion?: never` accepts `eqlVersion: undefined` without
  // `exactOptionalPropertyTypes` (not enabled in this repo) and cannot be made to
  // reject it, so a bare presence check threw on a config the declarations had
  // already accepted. Tolerating that one value keeps the type and the runtime in
  // agreement — and, like every other rule here, must match the native entry.
  it('tolerates an explicitly undefined eqlVersion, matching the native entry', async () => {
    await expect(
      Encryption({
        schemas: [users],
        config: { ...config, eqlVersion: undefined },
      }),
    ).resolves.toBeDefined()
    expect(newClientOpts().eqlVersion).toBe(3)
  })

  // The runtime `!schemas.length` guard was pinned only by a `@ts-expect-error`
  // type test (wasm-inline-schemas.test-d.ts), which never executes — deleting
  // the runtime throw left everything green. This executes it.
  it('rejects an empty schemas array at runtime, before touching newClient', async () => {
    await expect(
      Encryption({
        schemas: [] as unknown as [typeof users],
        config,
      }),
    ).rejects.toThrow(/At least one encryptedTable must be provided/)
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
