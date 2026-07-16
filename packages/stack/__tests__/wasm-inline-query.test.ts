import { beforeEach, describe, expect, it, vi } from 'vitest'

// #662: the WASM entry omitted `encryptQuery` entirely, making searchable
// encryption architecturally impossible on Deno/edge. These tests pin the new
// surface: index-type resolution (a local port of the native client's
// `resolveIndexType` — keep behaviour in lockstep), the FFI opts shape, null
// handling, and bulk position-stability. The protect-ffi WASM module is
// mocked; live coverage runs in the Deno e2e.

const ffi = vi.hoisted(() => ({
  newClient: vi.fn(async () => ({ handle: 'wasm-client' })),
  encrypt: vi.fn(async () => ({ v: 3, i: {}, c: 'ct' })),
  decrypt: vi.fn(async () => 'plain'),
  isEncrypted: vi.fn(() => true),
  encryptQuery: vi.fn(async () => ({ v: 3, i: { t: 'users', c: 'email' } })),
  encryptQueryBulk: vi.fn(
    async (_client: unknown, { terms }: { terms: unknown[] }) =>
      terms.map((_, n) => ({ v: 3, n })),
  ),
}))
vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ffi)
vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    create: vi.fn(() => ({
      data: { getToken: async () => ({ token: 'test' }) },
    })),
  },
  OidcFederationStrategy: {},
}))

import { encryptedTable, types } from '../src/eql/v3'
import { Encryption } from '../src/wasm-inline'

const users = encryptedTable('users', {
  // TextEq → unique index only
  email: types.TextEq('email'),
  // TextSearch → match (free-text) index
  bio: types.TextSearch('bio'),
  // Json → ste_vec
  prefs: types.Json('prefs'),
})

async function client() {
  return Encryption({
    schemas: [users],
    config: {
      workspaceCrn: 'crn:test:ws',
      accessKey: 'test-key',
      clientId: 'id',
      clientKey: 'key',
    },
  })
}

describe('WasmEncryptionClient.encryptQuery', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('resolves the index type from the column when queryType is omitted', async () => {
    const c = await client()
    await c.encryptQuery('a@b.com', { table: users, column: users.email })

    expect(ffi.encryptQuery).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        plaintext: 'a@b.com',
        table: 'users',
        column: 'email',
        indexType: 'unique',
      }),
    )
  })

  it('honours an explicit queryType and maps it to the FFI index', async () => {
    const c = await client()
    await c.encryptQuery('needle', {
      table: users,
      column: users.bio,
      queryType: 'freeTextSearch',
    })

    expect(ffi.encryptQuery).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ indexType: 'match' }),
    )
  })

  it('rejects a queryType the column is not indexed for', async () => {
    const c = await client()
    await expect(
      c.encryptQuery('a@b.com', {
        table: users,
        column: users.email,
        queryType: 'freeTextSearch',
      }),
    ).rejects.toThrow(/not configured on column "email"/)
    expect(ffi.encryptQuery).not.toHaveBeenCalled()
  })

  it('infers ste_vec queryOp from the plaintext shape (searchableJson)', async () => {
    const c = await client()
    await c.encryptQuery('$.user.email', {
      table: users,
      column: users.prefs,
      queryType: 'searchableJson',
    })
    expect(ffi.encryptQuery).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        indexType: 'ste_vec',
        queryOp: 'ste_vec_selector',
      }),
    )

    await c.encryptQuery(
      { role: 'admin' },
      { table: users, column: users.prefs, queryType: 'searchableJson' },
    )
    expect(ffi.encryptQuery).toHaveBeenLastCalledWith(
      expect.anything(),
      expect.objectContaining({
        indexType: 'ste_vec',
        queryOp: 'ste_vec_term',
      }),
    )
  })

  it('returns null for null plaintext without calling the FFI', async () => {
    const c = await client()
    expect(
      await c.encryptQuery(null, { table: users, column: users.email }),
    ).toBeNull()
    expect(ffi.encryptQuery).not.toHaveBeenCalled()
  })
})

describe('WasmEncryptionClient.encryptQueryBulk', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('is position-stable: null values yield null at the same index', async () => {
    const c = await client()
    const out = await c.encryptQueryBulk([
      { value: 'a@b.com', table: users, column: users.email },
      { value: null as unknown as string, table: users, column: users.email },
      {
        value: 'needle',
        table: users,
        column: users.bio,
        // TextSearch carries unique+ore+match; explicit queryType targets
        // the free-text index (inference would pick unique by priority,
        // matching the native client).
        queryType: 'freeTextSearch' as const,
      },
    ])

    expect(out).toHaveLength(3)
    expect(out[0]).toEqual({ v: 3, n: 0 })
    expect(out[1]).toBeNull()
    expect(out[2]).toEqual({ v: 3, n: 1 })
    // Only the two live terms reached the FFI, with per-term resolution.
    const { terms } = ffi.encryptQueryBulk.mock.calls[0][1] as {
      terms: Array<{ indexType: string }>
    }
    expect(terms.map((t) => t.indexType)).toEqual(['unique', 'match'])
  })

  it('short-circuits an all-null batch', async () => {
    const c = await client()
    const out = await c.encryptQueryBulk([
      { value: null as unknown as string, table: users, column: users.email },
    ])
    expect(out).toEqual([null])
    expect(ffi.encryptQueryBulk).not.toHaveBeenCalled()
  })
})
