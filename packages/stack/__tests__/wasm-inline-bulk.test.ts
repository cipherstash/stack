import { beforeEach, describe, expect, it, vi } from 'vitest'

// #737: the WASM entry exposed no bulk operations, so an N-row list on the
// edge cost N ZeroKMS round trips. These tests pin the new surface: the FFI
// payload shape (`{ plaintext, table, column }` / `{ ciphertext }` — the
// protect-ffi `EncryptPayload` has no `id`, unlike the native entry's), that
// exactly ONE FFI call is made per batch (the whole point), position
// stability across nulls, and the per-index failure reporting that
// `decryptBulkFallible` makes possible. protect-ffi is mocked; live coverage
// runs in the Deno e2e.

const ffi = vi.hoisted(() => ({
  newClient: vi.fn(async () => ({ handle: 'wasm-client' })),
  encrypt: vi.fn(async () => ({ v: 3, i: {}, c: 'ct' })),
  decrypt: vi.fn(async () => 'plain'),
  isEncrypted: vi.fn(() => true),
  encryptQuery: vi.fn(async () => ({ v: 3, i: {} })),
  encryptQueryBulk: vi.fn(
    async (_client: unknown, { queries }: { queries: unknown[] }) =>
      queries.map((_, n) => ({ v: 3, n })),
  ),
  encryptBulk: vi.fn(
    async (_client: unknown, { plaintexts }: { plaintexts: unknown[] }) =>
      plaintexts.map((_, n) => ({ v: 3, i: {}, c: `ct-${n}` })),
  ),
  decryptBulkFallible: vi.fn(
    async (_client: unknown, { ciphertexts }: { ciphertexts: unknown[] }) =>
      ciphertexts.map((_, n) => ({ data: `plain-${n}` })),
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
  email: types.TextEq('email'),
  bio: types.TextSearch('bio'),
})

// A column whose declared DB name differs from the property, so the payload
// assertion proves `getColumnName` is applied rather than the property key.
const accounts = encryptedTable('accounts', {
  emailAddress: types.TextEq('email_address'),
})

async function client() {
  return Encryption({
    schemas: [users, accounts],
    config: {
      workspaceCrn: 'crn:test:ws',
      accessKey: 'test-key',
      clientId: 'id',
      clientKey: 'key',
    },
  })
}

const ct = (c: string) => ({ v: 3, i: { t: 'users', c: 'email' }, c }) as never

describe('WasmEncryptionClient.bulkEncrypt', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('sends one FFI call for the whole batch', async () => {
    const c = await client()
    await c.bulkEncrypt([
      { plaintext: 'a@b.com', table: users, column: users.email },
      { plaintext: 'hello', table: users, column: users.bio },
      { plaintext: 'c@d.com', table: users, column: users.email },
    ])

    // The entire reason this method exists: 3 values, 1 round trip.
    expect(ffi.encryptBulk).toHaveBeenCalledTimes(1)
    expect(ffi.encrypt).not.toHaveBeenCalled()
  })

  it('builds the FFI payload as { plaintext, table, column } with no id', async () => {
    const c = await client()
    await c.bulkEncrypt([
      { plaintext: 'a@b.com', table: users, column: users.email },
      { plaintext: 'hello', table: users, column: users.bio },
    ])

    const [, opts] = ffi.encryptBulk.mock.calls[0]
    expect(opts.plaintexts).toEqual([
      { plaintext: 'a@b.com', table: 'users', column: 'email' },
      { plaintext: 'hello', table: 'users', column: 'bio' },
    ])
    // protect-ffi's EncryptPayload has no `id` — the native entry's is
    // dropped at the boundary, so sending one would be dead weight.
    for (const p of opts.plaintexts as Array<Record<string, unknown>>) {
      expect(p).not.toHaveProperty('id')
    }
  })

  it('mixes tables and columns in a single batch', async () => {
    const c = await client()
    await c.bulkEncrypt([
      { plaintext: 'a@b.com', table: users, column: users.email },
      {
        plaintext: 'x@y.com',
        table: accounts,
        column: accounts.emailAddress,
      },
    ])

    const [, opts] = ffi.encryptBulk.mock.calls[0]
    expect(opts.plaintexts).toEqual([
      { plaintext: 'a@b.com', table: 'users', column: 'email' },
      // The DECLARED column name, not the property key.
      { plaintext: 'x@y.com', table: 'accounts', column: 'email_address' },
    ])
  })

  it('is position-stable across null and undefined plaintexts', async () => {
    const c = await client()
    const out = await c.bulkEncrypt([
      { plaintext: null, table: users, column: users.email },
      { plaintext: 'a@b.com', table: users, column: users.email },
      { plaintext: undefined, table: users, column: users.email },
      { plaintext: 'c@d.com', table: users, column: users.email },
    ])

    const values = expectData(out)
    expect(values).toHaveLength(4)
    expect(values[0]).toBeNull()
    expect(values[2]).toBeNull()
    // Live values keep their ORIGINAL indices, not their compacted ones.
    expect(values[1]).toEqual({ v: 3, i: {}, c: 'ct-0' })
    expect(values[3]).toEqual({ v: 3, i: {}, c: 'ct-1' })

    // Nulls never reach ZeroKMS.
    const [, opts] = ffi.encryptBulk.mock.calls[0]
    expect(opts.plaintexts).toHaveLength(2)
  })

  it('short-circuits an all-null batch without calling the FFI', async () => {
    const c = await client()
    const out = await c.bulkEncrypt([
      { plaintext: null, table: users, column: users.email },
      { plaintext: undefined, table: users, column: users.email },
    ])

    expect(out).toEqual({ data: [null, null] })
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
  })

  it('returns an empty array for an empty batch, with no FFI call', async () => {
    const c = await client()
    expect(await c.bulkEncrypt([])).toEqual({ data: [] })
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
  })
})

describe('WasmEncryptionClient.bulkDecrypt', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('sends one FFI call for the whole batch', async () => {
    const c = await client()
    await c.bulkDecrypt([ct('a'), ct('b'), ct('c')])

    expect(ffi.decryptBulkFallible).toHaveBeenCalledTimes(1)
    expect(ffi.decrypt).not.toHaveBeenCalled()
  })

  it('builds the FFI payload as { ciphertext }', async () => {
    const c = await client()
    const a = ct('a')
    const b = ct('b')
    await c.bulkDecrypt([a, b])

    const [, opts] = ffi.decryptBulkFallible.mock.calls[0]
    expect(opts.ciphertexts).toEqual([{ ciphertext: a }, { ciphertext: b }])
  })

  it('is position-stable across null and undefined ciphertexts', async () => {
    const c = await client()
    const out = await c.bulkDecrypt([null, ct('a'), undefined, ct('b')])

    expect(out).toEqual({ data: [null, 'plain-0', null, 'plain-1'] })
    const [, opts] = ffi.decryptBulkFallible.mock.calls[0]
    expect(opts.ciphertexts).toHaveLength(2)
  })

  it('short-circuits an all-null batch without calling the FFI', async () => {
    const c = await client()
    expect(await c.bulkDecrypt([null, undefined])).toEqual({
      data: [null, null],
    })
    expect(ffi.decryptBulkFallible).not.toHaveBeenCalled()
  })

  it('reports EVERY failing index, not just the first', async () => {
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { data: 'ok' },
      { error: 'boom-one' },
      { error: 'boom-two' },
    ] as never)

    const c = await client()
    // Indices are into the INPUT array, so the leading null shifts them:
    // input 1/2/3 map to live 0/1/2, and the two failures are inputs 2 and 3.
    await expect(
      c.bulkDecrypt([null, ct('a'), ct('b'), ct('c')]),
    ).resolves.toMatchObject({
      failure: {
        type: 'DecryptionError',
        message: expect.stringMatching(/failed for 2 of 3 payload\(s\)/),
      },
    })

    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { data: 'ok' },
      { error: 'boom-one' },
      { error: 'boom-two' },
    ] as never)
    const res = await c.bulkDecrypt([null, ct('a'), ct('b'), ct('c')])

    expect(res.failure?.message).toContain('[2]: boom-one')
    expect(res.failure?.message).toContain('[3]: boom-two')
  })

  it('succeeds when every item decrypts', async () => {
    const c = await client()
    await expect(c.bulkDecrypt([ct('a'), ct('b')])).resolves.toEqual({
      data: ['plain-0', 'plain-1'],
    })
  })
})

// Results are matched to inputs BY POSITION — the FFI payloads carry no
// correlation id. A short response would otherwise leave trailing slots null,
// which a caller cannot tell apart from "this row had no value".
// The live-filters test `!== null && !== undefined` deliberately, NOT
// truthiness. If any regressed to a truthy check, `0` / `''` / `false` would
// be treated as absent: real values silently persisted as NULL, with the whole
// suite still green. This is the highest-consequence regression the batch code
// can have, so it is pinned per method.
describe('falsy-but-live values still reach ZeroKMS', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('bulkEncrypt sends 0, empty string and false', async () => {
    const c = await client()
    const out = await c.bulkEncrypt([
      { plaintext: 0, table: users, column: users.email },
      { plaintext: '', table: users, column: users.email },
      { plaintext: false, table: users, column: users.email },
    ])

    const [, opts] = ffi.encryptBulk.mock.calls[0]
    const sent = opts.plaintexts as Array<{ plaintext: unknown }>
    expect(sent.map((p) => p.plaintext)).toEqual([0, '', false])
    // …and each comes back at its own index, not as a null hole.
    expect(expectData(out)).toEqual([
      { v: 3, i: {}, c: 'ct-0' },
      { v: 3, i: {}, c: 'ct-1' },
      { v: 3, i: {}, c: 'ct-2' },
    ])
  })

  it('encryptQueryBulk sends 0, empty string and false', async () => {
    const c = await client()
    await c.encryptQueryBulk([
      { value: 0, table: users, column: users.email },
      { value: '', table: users, column: users.email },
      { value: false, table: users, column: users.email },
    ])
    expect(ffi.encryptQueryBulk).toHaveBeenCalledTimes(1)
    const [, opts] = ffi.encryptQueryBulk.mock.calls[0]
    expect(opts.queries).toHaveLength(3)
  })
})

// A sparse input (e.g. a partially-filled `new Array(n)`) must still yield a
// dense, index-aligned result. `Array.prototype.map` SKIPS holes, so building
// the output with `map` left `undefined` holes rather than the documented
// `null` — while lengths still matched, so the batch-length guard could not
// see it.
it('bulkDecrypt returns null (not a hole) for a sparse input slot', async () => {
  const c = await client()
  const sparse: Array<ReturnType<typeof ct> | undefined> = new Array(3)
  sparse[0] = ct('a')
  sparse[2] = ct('b')

  const out = expectData(await c.bulkDecrypt(sparse))
  expect(out).toHaveLength(3)
  expect(out[1]).toBeNull()
  expect(1 in out, 'index 1 must be a real null, not a hole').toBe(true)
})

// `encryptQueryBulk` gained the same length guard as the other two, but the
// mismatch describe below only covered bulkEncrypt/bulkDecrypt — dropping the
// guard here would have passed the whole suite.
it('encryptQueryBulk fails on a short FFI response', async () => {
  ffi.encryptQueryBulk.mockResolvedValueOnce([{ v: 3, n: 0 }])

  const c = await client()
  await expect(
    c.encryptQueryBulk([
      { value: 'a', table: users, column: users.email },
      { value: 'b', table: users, column: users.email },
    ]),
  ).resolves.toMatchObject({
    failure: {
      message: expect.stringMatching(/sent 2 payload\(s\).*received 1 back/s),
    },
  })
})

describe('bulk result/input length mismatch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('bulkEncrypt fails rather than returning a partially-null batch', async () => {
    ffi.encryptBulk.mockResolvedValueOnce([{ v: 3, i: {}, c: 'only-one' }])

    const c = await client()
    await expect(
      c.bulkEncrypt([
        { plaintext: 'a', table: users, column: users.email },
        { plaintext: 'b', table: users, column: users.email },
      ]),
    ).resolves.toMatchObject({
      failure: {
        message: expect.stringMatching(/sent 2 payload\(s\).*received 1 back/s),
      },
    })
  })

  it('bulkDecrypt fails rather than returning a partially-null batch', async () => {
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { data: 'only-one' },
    ] as never)

    const c = await client()
    await expect(c.bulkDecrypt([ct('a'), ct('b')])).resolves.toMatchObject({
      failure: {
        message: expect.stringMatching(/sent 2 payload\(s\).*received 1 back/s),
      },
    })
  })
})
