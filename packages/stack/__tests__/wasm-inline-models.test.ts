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
    // `toStrictEqual`, not `toEqual`: the point of this test is that an
    // explicit `undefined` is PRESERVED in place, and `toEqual` treats an
    // `undefined` property as absent — it would pass even if `createdOn` were
    // dropped entirely.
    expect(expectData(out)).toStrictEqual({
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

// #742 review: the shared traversal was rewritten to be non-mutating and
// unambiguous. These pin the behaviours that were bugs before the rewrite.
describe('WasmEncryptionClient model helpers — hardening (#742 review)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('does not mutate the caller model on encrypt (nested column)', async () => {
    const c = await client()
    const input = { profile: { ssn: '123-45-6789', nick: 'al' } }
    const out = await c.encryptModel(input, patients)

    // The caller's own object is untouched — no envelope written back in.
    expect(input.profile.ssn).toBe('123-45-6789')
    expect(input.profile.nick).toBe('al')
    const data = expectData(out) as { profile: { ssn: unknown; nick: string } }
    expect(data.profile.ssn).toEqual({ v: 3, i: {}, c: 'ct-0' })
    // The returned object is independent of the input.
    expect(data.profile).not.toBe(input.profile)
  })

  it('does not write decrypted plaintext back into the caller (nested)', async () => {
    const c = await client()
    const envelope = ct('a')
    const input = { profile: { ssn: envelope } }
    const out = await c.decryptModel(input, patients)

    // The input the caller believes is still encrypted is unchanged.
    expect(input.profile.ssn).toBe(envelope)
    const data = expectData(out) as { profile: { ssn: unknown } }
    expect(data.profile.ssn).toBe('plain-0')
  })

  it('normalizes a literal flat dotted key without crashing or leaking plaintext', async () => {
    const c = await client()
    const out = await c.encryptModel(
      { 'profile.ssn': 'secret' } as never,
      patients,
    )
    const data = expectData(out) as Record<string, unknown> & {
      profile?: { ssn?: unknown }
    }
    // The flat plaintext key is gone; the field is encrypted at its column path.
    expect(data['profile.ssn']).toBeUndefined()
    expect(data.profile?.ssn).toEqual({ v: 3, i: {}, c: 'ct-0' })
  })

  it('passes an already-encrypted schema field through without re-encrypting', async () => {
    const c = await client()
    const existing = ct('already')
    const out = await c.encryptModel({ email: existing, id: 1 } as never, users)

    expect(ffi.encryptBulk).not.toHaveBeenCalled()
    const data = expectData(out) as { email: unknown; id: number }
    expect(data.email).toBe(existing)
    expect(data.id).toBe(1)
  })

  it('rejects a non-object model element with a clear failure', async () => {
    const c = await client()
    const out = await c.bulkEncryptModels(['x@y.com'] as never, users)
    expect(out.failure?.type).toBe('EncryptionError')
    expect(out.failure?.message).toContain(
      'each model must be a non-null object',
    )
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
  })

  it('returns { data: [] } for a null or undefined models argument', async () => {
    const c = await client()
    expect(await c.bulkEncryptModels(null as never, users)).toEqual({
      data: [],
    })
    expect(await c.bulkDecryptModels(undefined as never, users)).toEqual({
      data: [],
    })
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
    expect(ffi.decryptBulkFallible).not.toHaveBeenCalled()
  })

  it('fails decrypt against a table the client was not initialized with', async () => {
    const c = await client()
    const foreign = encryptedTable('foreign', { x: types.TextEq('x') })
    const out = await c.decryptModel({ x: ct('a') }, foreign)
    expect(out.failure?.type).toBe('DecryptionError')
    expect(out.failure?.message).toContain(
      'not one this client was initialized with',
    )
    expect(ffi.decryptBulkFallible).not.toHaveBeenCalled()
  })

  it('fails encrypt against a table the client was not initialized with', async () => {
    const c = await client()
    const foreign = encryptedTable('foreign', { x: types.TextEq('x') })
    // Both encrypt entrypoints call `requireTable`; cover them symmetrically
    // with the decrypt case above.
    const single = await c.encryptModel({ x: 'secret' }, foreign)
    expect(single.failure?.type).toBe('EncryptionError')
    expect(single.failure?.message).toContain(
      'not one this client was initialized with',
    )
    const bulk = await c.bulkEncryptModels([{ x: 'secret' }], foreign)
    expect(bulk.failure?.type).toBe('EncryptionError')
    expect(bulk.failure?.message).toContain(
      'not one this client was initialized with',
    )
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
  })

  it('preserves a passthrough field literally named __proto__', async () => {
    const c = await client()
    // A non-schema, non-envelope field named `__proto__` (as `JSON.parse`
    // materialises it) is a passthrough value. Plain `out.__proto__ = value`
    // would hit the prototype setter and silently drop it; it must survive
    // verbatim as an own property, and the global prototype must stay intact.
    const model = JSON.parse('{"id":1,"__proto__":{"kept":true}}')
    const out = await c.encryptModel(model, users)

    expect(ffi.encryptBulk).not.toHaveBeenCalled()
    const data = expectData(out) as Record<string, unknown>
    // Stored as an OWN data property, not swallowed by the prototype setter.
    expect(Object.getOwnPropertyNames(data)).toContain('__proto__')
    expect(Object.getOwnPropertyDescriptor(data, '__proto__')?.value).toEqual({
      kept: true,
    })
    // Untouched global prototype: no `kept` leaked onto `Object.prototype`.
    expect('kept' in {}).toBe(false)
  })

  it('rejects an invalid Date with a field-named failure, before the FFI', async () => {
    const c = await client()
    const out = await c.encryptModel(
      { createdOn: new Date(Number.NaN) } as never,
      users,
    )
    expect(out.failure?.type).toBe('EncryptionError')
    expect(out.failure?.message).toContain('createdOn')
    expect(ffi.encryptBulk).not.toHaveBeenCalled()
  })

  it('refuses a __proto__ dotted key instead of polluting the prototype', async () => {
    const c = await client()
    // A DB-influenced model with a prototype-shaped own key holding an envelope.
    const malicious = JSON.parse(
      `{"__proto__.toString": ${JSON.stringify(ct('x'))}}`,
    )
    const out = await c.decryptModel(malicious, patients)

    expect(out.failure?.type).toBe('DecryptionError')
    expect(out.failure?.message).toContain('Forbidden key')
    // The global prototype is intact.
    expect(typeof {}.toString).toBe('function')
  })

  it('rebuilds a valid Date but keeps an unparseable date value as-is', async () => {
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { data: 'not-a-date' },
    ] as never)
    const c = await client()
    const out = await c.decryptModel({ createdOn: ct('d') }, users)
    // No silent Invalid Date object — the raw value is returned instead.
    expect(expectData(out).createdOn).toBe('not-a-date')
  })

  it('normalizes a Date at the value-level bulkEncrypt crossing (no `{}` corruption)', async () => {
    const c = await client()
    await c.bulkEncrypt([
      {
        // A plain-JS caller can pass a Date the WasmPlaintext type forbids.
        plaintext: new Date('2026-07-22T00:00:00.000Z') as never,
        table: users,
        column: users.createdOn,
      },
    ])
    const opts = ffi.encryptBulk.mock.calls[0][1] as {
      plaintexts: Array<{ plaintext: unknown }>
    }
    expect(opts.plaintexts[0].plaintext).toBe('2026-07-22T00:00:00.000Z')
  })
})
