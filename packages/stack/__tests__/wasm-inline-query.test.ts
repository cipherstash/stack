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
    async (_client: unknown, { queries }: { queries: unknown[] }) =>
      queries.map((_, n) => ({ v: 3, n })),
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
import { expectData } from './helpers/expect-result'

const users = encryptedTable('users', {
  // TextEq → unique index only
  email: types.TextEq('email'),
  // TextSearch → unique + ope + match
  bio: types.TextSearch('bio'),
  // IntegerOrd → ope only (the OPE ordering flavour, no unique)
  age: types.IntegerOrd('age'),
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
    // WASM serde rejects explicitly-undefined fields — queryOp must be
    // OMITTED for non-JSON query types, not passed as undefined.
    expect(
      'queryOp' in
        (ffi.encryptQuery.mock.calls[0][1] as Record<string, unknown>),
    ).toBe(false)
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

  it("swaps orderAndRange's static 'ore' for the v3 ord domain's 'ope'", async () => {
    // The live Deno matrix caught this: v3 `_ord` domains carry `ope`, not
    // `ore` — the shared resolver (now used verbatim instead of a local
    // port) swaps to the ordering index the column actually configures.
    const c = await client()
    await c.encryptQuery(42, {
      table: users,
      column: users.age,
      queryType: 'orderAndRange',
    })
    expect(ffi.encryptQuery).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ indexType: 'ope' }),
    )
  })

  it('answers equality via the ordering index on order-capable columns without unique', async () => {
    const c = await client()
    await c.encryptQuery(42, {
      table: users,
      column: users.age,
      queryType: 'equality',
    })
    expect(ffi.encryptQuery).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ indexType: 'ope' }),
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
    ).resolves.toMatchObject({
      failure: {
        type: 'EncryptionError',
        message: expect.stringMatching(/not configured on column "email"/),
      },
    })
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
        queryOp: 'default',
      }),
    )
  })

  it('returns null for null plaintext without calling the FFI', async () => {
    const c = await client()
    expect(
      await c.encryptQuery(null, { table: users, column: users.email }),
    ).toEqual({ data: null })
    expect(ffi.encryptQuery).not.toHaveBeenCalled()
  })

  // The same pre-FFI guards the native client runs — an invalid value must
  // fail with the NAMED error before any FFI/network crossing, not with an
  // opaque serde failure (or a silently no-match term) from inside WASM.
  it('rejects NaN with the named validation error before the FFI', async () => {
    const c = await client()
    await expect(
      c.encryptQuery(Number.NaN, {
        table: users,
        column: users.age,
        queryType: 'orderAndRange',
      }),
    ).resolves.toMatchObject({
      failure: { message: '[encryption]: Cannot encrypt NaN value' },
    })
    expect(ffi.encryptQuery).not.toHaveBeenCalled()
  })

  it('rejects a numeric value against a match index before the FFI', async () => {
    const c = await client()
    await expect(
      c.encryptQuery(42, {
        table: users,
        column: users.bio,
        queryType: 'freeTextSearch',
      }),
    ).resolves.toMatchObject({
      failure: {
        message: expect.stringMatching(
          /Cannot use 'match' index with numeric value/,
        ),
      },
    })
    expect(ffi.encryptQuery).not.toHaveBeenCalled()
  })

  it('applies the same validation on the bulk path', async () => {
    const c = await client()
    await expect(
      c.encryptQueryBulk([
        {
          value: Number.POSITIVE_INFINITY,
          table: users,
          column: users.age,
          queryType: 'orderAndRange',
        },
      ]),
    ).resolves.toMatchObject({
      failure: { message: '[encryption]: Cannot encrypt Infinity value' },
    })
    expect(ffi.encryptQueryBulk).not.toHaveBeenCalled()
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
      { value: null, table: users, column: users.email },
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

    const terms = expectData(out)
    expect(terms).toHaveLength(3)
    expect(terms[0]).toEqual({ v: 3, n: 0 })
    expect(terms[1]).toBeNull()
    expect(terms[2]).toEqual({ v: 3, n: 1 })
    // Only the two live terms reached the FFI, with per-term resolution.
    const { queries } = ffi.encryptQueryBulk.mock.calls[0][1] as {
      queries: Array<{ indexType: string }>
    }
    expect(queries.map((t) => t.indexType)).toEqual(['unique', 'match'])
  })

  it('short-circuits an all-null batch', async () => {
    const c = await client()
    const out = await c.encryptQueryBulk([
      { value: null, table: users, column: users.email },
    ])
    expect(out).toEqual({ data: [null] })
    expect(ffi.encryptQueryBulk).not.toHaveBeenCalled()
  })
})
