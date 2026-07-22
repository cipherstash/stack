import { beforeEach, describe, expect, it, vi } from 'vitest'

// #742: the WASM entry had no model helpers, so edge code hand-rolled the
// field-by-field mapping that `encryptModel` exists to make impossible to get
// wrong (forget one field in the hand-written version and it persists in
// PLAINTEXT). These tests pin the ported surface: schema fields are matched by
// JS property name and addressed at the FFI by DB column name, the whole
// model (or list of models) is ONE FFI crossing, nulls and passthrough fields
// survive verbatim, Date columns round-trip Date → ISO string → Date, and
// failures come back as this entry's `{ failure }` Results with per-field
// coordinates. protect-ffi is mocked; live coverage runs in the Deno e2e.

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

// `createdOn` → `created_on` pins the two keyings apart: models are matched
// by JS property name, the FFI payload is addressed by DB column name.
const users = encryptedTable('users', {
  email: types.TextEq('email'),
  createdOn: types.Date('created_on'),
})

// A flat dotted column path — the v3 way to declare a nested field. The
// model carries `{ profile: { ssn } }`; the walk matches it via the path.
const patients = encryptedTable('patients', {
  'profile.ssn': types.TextEq('profile.ssn'),
})

async function client() {
  return Encryption({
    schemas: [users, patients],
    config: {
      workspaceCrn: 'crn:test:ws',
      accessKey: 'test-key',
      clientId: 'id',
      clientKey: 'key',
    },
  })
}

/** A structurally-valid EQL envelope, as `isEncryptedPayload` recognises. */
const ct = (c: string) => ({ v: 3, i: { t: 'users', c: 'email' }, c }) as never

describe('WasmEncryptionClient.encryptModel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('encrypts only schema fields, in one FFI call, addressed by DB name', async () => {
    const c = await client()
    const out = await c.encryptModel(
      {
        id: 42,
        email: 'alice@example.com',
        createdOn: new Date('2026-07-22T00:00:00.000Z'),
        role: 'admin',
      },
      users,
    )

    expect(ffi.encryptBulk).toHaveBeenCalledTimes(1)
    expect(ffi.encrypt).not.toHaveBeenCalled()
    const [, opts] = ffi.encryptBulk.mock.calls[0]
    expect(opts.plaintexts).toEqual([
      { plaintext: 'alice@example.com', table: 'users', column: 'email' },
      // Date → ISO string: the wasm serde cannot carry a Date, and the DB
      // name (`created_on`) proves the property→DB mapping is applied.
      {
        plaintext: '2026-07-22T00:00:00.000Z',
        table: 'users',
        column: 'created_on',
      },
    ])

    const data = expectData(out)
    // Passthrough fields survive verbatim; schema fields are envelopes.
    expect(data.id).toBe(42)
    expect(data.role).toBe('admin')
    expect(data.email).toEqual({ v: 3, i: {}, c: 'ct-0' })
    expect(data.createdOn).toEqual({ v: 3, i: {}, c: 'ct-1' })
  })

  it('passes null and undefined schema fields through without encrypting them', async () => {
    const c = await client()
    // `V3ModelInput` types a schema field as `T | null` — an explicit
    // `undefined` is a plain-JS-caller shape, which the runtime preserves
    // verbatim rather than encrypting. The cast simulates that caller.
    const model = { email: null, createdOn: undefined, id: 1 }
    const out = await c.encryptModel(
      model as unknown as { email: null; id: number },
      users,
    )

    expect(ffi.encryptBulk).not.toHaveBeenCalled()
    expect(expectData(out)).toEqual({
      email: null,
      createdOn: undefined,
      id: 1,
    })
  })

  it('encrypts a nested field declared as a dotted column path', async () => {
    const c = await client()
    const out = await c.encryptModel(
      { profile: { ssn: '123-45-6789', nickname: 'al' } },
      patients,
    )

    const [, opts] = ffi.encryptBulk.mock.calls[0]
    expect(opts.plaintexts).toEqual([
      { plaintext: '123-45-6789', table: 'patients', column: 'profile.ssn' },
    ])
    const data = expectData(out) as {
      profile: { ssn: unknown; nickname: string }
    }
    expect(data.profile.ssn).toEqual({ v: 3, i: {}, c: 'ct-0' })
    expect(data.profile.nickname).toBe('al')
  })

  it('rejects an out-of-range numeric plaintext as a { failure }, before the FFI', async () => {
    const c = await client()
    // The type system already rejects this shape — the cast simulates a
    // plain-JS caller, which is exactly who the runtime guard exists for.
    const out = await c.encryptModel(
      { email: Number.NaN } as unknown as { email: string },
      users,
    )

    expect(out.failure?.type).toBe('EncryptionError')
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
  })

  it('refuses a short FFI response instead of silently dropping fields', async () => {
    ffi.encryptBulk.mockResolvedValueOnce([{ v: 3, i: {}, c: 'only-one' }])

    const c = await client()
    const out = await c.encryptModel(
      { email: 'a@b.com', createdOn: new Date(0) },
      users,
    )

    expect(out.failure?.type).toBe('EncryptionError')
    expect(out.failure?.message).toMatch(/sent 2 payload\(s\).*received 1/)
  })
})

describe('WasmEncryptionClient.decryptModel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('decrypts every envelope in one FFI call and leaves the rest alone', async () => {
    const c = await client()
    const out = await c.decryptModel(
      { id: 7, email: ct('a'), note: 'plain', missing: null },
      users,
    )

    expect(ffi.decryptBulkFallible).toHaveBeenCalledTimes(1)
    const [, opts] = ffi.decryptBulkFallible.mock.calls[0]
    expect(opts.ciphertexts).toEqual([{ ciphertext: ct('a') }])

    expect(expectData(out)).toEqual({
      id: 7,
      email: 'plain-0',
      note: 'plain',
      missing: null,
    })
  })

  it('rebuilds date-like columns into Date values from cast_as', async () => {
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { data: '2026-07-22T01:02:03.000Z' },
    ] as never)

    const c = await client()
    const out = await c.decryptModel({ createdOn: ct('d') }, users)

    const data = expectData(out)
    expect(data.createdOn).toBeInstanceOf(Date)
    expect((data.createdOn as Date).toISOString()).toBe(
      '2026-07-22T01:02:03.000Z',
    )
  })

  it('names every failed field by its model path', async () => {
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { error: 'boom', code: 'CT_ERROR' },
    ] as never)

    const c = await client()
    const out = await c.decryptModel({ profile: { ssn: ct('x') } }, patients)

    expect(out.failure?.type).toBe('DecryptionError')
    expect(out.failure?.message).toMatch(/failed for 1 of 1 payload\(s\)/)
    expect(out.failure?.message).toContain('profile.ssn (CT_ERROR): boom')
  })
})

describe('WasmEncryptionClient.bulkEncryptModels', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('batches every field of every model into one FFI call', async () => {
    const c = await client()
    const out = await c.bulkEncryptModels(
      [
        { email: 'a@b.com', id: 1 },
        { email: 'c@d.com', id: 2 },
      ],
      users,
    )

    expect(ffi.encryptBulk).toHaveBeenCalledTimes(1)
    const [, opts] = ffi.encryptBulk.mock.calls[0]
    expect(opts.plaintexts).toHaveLength(2)

    const data = expectData(out)
    expect(data).toEqual([
      { email: { v: 3, i: {}, c: 'ct-0' }, id: 1 },
      { email: { v: 3, i: {}, c: 'ct-1' }, id: 2 },
    ])
  })

  it('returns an empty array for an empty batch, with no FFI call', async () => {
    const c = await client()
    expect(await c.bulkEncryptModels([], users)).toEqual({ data: [] })
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
  })
})

describe('WasmEncryptionClient.bulkDecryptModels', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('maps decrypted fields back to the right models from one FFI call', async () => {
    const c = await client()
    const out = await c.bulkDecryptModels(
      [
        { email: ct('a'), id: 1 },
        { email: ct('b'), id: 2, note: null },
      ],
      users,
    )

    expect(ffi.decryptBulkFallible).toHaveBeenCalledTimes(1)
    expect(expectData(out)).toEqual([
      { email: 'plain-0', id: 1 },
      { email: 'plain-1', id: 2, note: null },
    ])
  })

  it('labels failures with the model index and field path', async () => {
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { data: 'ok' },
      { error: 'boom' },
    ] as never)

    const c = await client()
    const out = await c.bulkDecryptModels(
      [{ email: ct('a') }, { email: ct('b') }],
      users,
    )

    expect(out.failure?.type).toBe('DecryptionError')
    expect(out.failure?.message).toContain('[model 1] email: boom')
  })

  it('returns an empty array for an empty batch, with no FFI call', async () => {
    const c = await client()
    expect(await c.bulkDecryptModels([], users)).toEqual({ data: [] })
    expect(ffi.decryptBulkFallible).not.toHaveBeenCalled()
  })
})
