/**
 * Live end-to-end tests for `encryptedDynamoDB` against EQL v3 tables (#657).
 *
 * Mirrors the v2 suite in `encrypted-dynamodb.test.ts` and adds the two things
 * only v3 raises:
 *
 *  - both client shapes must work. `EncryptionV3` returns a `TypedEncryptionClient`
 *    whose `decryptModel` is a plain `Promise<Result<…>>` taking the table as a
 *    second argument; `Encryption({ config: { eqlVersion: 3 } })` returns the
 *    nominal chainable client. Audit metadata on decrypt only has somewhere to
 *    go on the latter.
 *  - per-domain storage: only equality domains mint the `hm` term that backs a
 *    DynamoDB key condition. Ordering and free-text terms are not stored.
 *
 * Requires CipherStash credentials (`CS_*`), like the rest of this suite.
 */
import 'dotenv/config'
import fc from 'fast-check'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { toItemWithEqlPayloads } from '@/dynamodb/helpers'
import type { EncryptedDynamoDBInstance } from '@/dynamodb/types'
import type { EncryptionClient } from '@/encryption'
import { EncryptionV3 } from '@/encryption/v3'
import type { JsonValue } from '@/eql/v3'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'

/**
 * This suite talks to live ZeroKMS. Skip (rather than fail) when the CipherStash
 * credentials are absent, so a local run without `.env` is green — matching the
 * four variables `requireIntegrationEnv(['cipherstash'])` checks. With creds
 * present the suite runs normally.
 */
const hasCipherStashCreds = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
].every((name) => Boolean(process.env[name]))

const users = encryptedTable('users_v3_dynamo', {
  email: types.TextEq('email'),
  name: types.Text('name'),
  age: types.IntegerOrd('age'),
  bio: types.TextSearch('bio'),
  meta: types.Json('meta'),
})

type User = {
  pk: string
  email?: string
  name?: string
  age?: number
  bio?: string
  // `Record<string, unknown>` would not compile against a `types.Json` column:
  // `unknown` is not a `JsonValue`. Naming the real element type is the point of
  // the v3 overload — it catches a model that claims to hold non-JSON.
  meta?: Record<string, JsonValue>
  role?: string
}

/** The typed client from `EncryptionV3` — the documented v3 entry point. */
let typedDynamo: EncryptedDynamoDBInstance
/** The nominal chainable client, forced into v3 mode. */
let nominalClient: EncryptionClient
let nominalDynamo: EncryptedDynamoDBInstance

beforeAll(async () => {
  // Nothing to set up when the suite is skipped for lack of credentials; the
  // client constructors below would otherwise fail to authenticate.
  if (!hasCipherStashCreds) return

  const typedClient = await EncryptionV3({ schemas: [users] })
  typedDynamo = encryptedDynamoDB({ encryptionClient: typedClient })

  nominalClient = await Encryption({
    schemas: [users] as never,
    config: { eqlVersion: 3 },
  })
  nominalDynamo = encryptedDynamoDB({ encryptionClient: nominalClient })
})

describe.skipIf(!hasCipherStashCreds)('encryptModel with a v3 table', () => {
  it('splits an equality domain into __source and __hmac', async () => {
    const result = await typedDynamo.encryptModel(
      { pk: 'user#1', email: 'alice@example.com', role: 'admin' },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(Object.keys(result.data).sort()).toEqual([
      'email__hmac',
      'email__source',
      'pk',
      'role',
    ])
    expect(typeof result.data.email__source).toBe('string')
    expect(typeof result.data.email__hmac).toBe('string')
    expect(result.data.email__source).not.toContain('alice@example.com')
  })

  it('regression: a v3 scalar is split, not written out as a raw map', async () => {
    const result = await typedDynamo.encryptModel(
      { pk: 'user#2', name: 'Bob' },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    // Before the port, gating on `k === 'ct'` meant untagged v3 scalars fell
    // through to the nested-object branch and were stored as `{ name: { v, i,
    // c } }` — no __source, and the ciphertext nested one level down.
    expect(result.data).toHaveProperty('name__source')
    expect(result.data).not.toHaveProperty('name')
    expect(typeof result.data.name__source).toBe('string')
  })

  it('gives an ordering domain a __source but no __hmac', async () => {
    const result = await typedDynamo.encryptModel(
      { pk: 'user#3', age: 42 },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    // `IntegerOrd` is equality-capable in Postgres via its ordering term, but
    // that term has no DynamoDB query surface, so nothing is stored for it.
    expect(result.data).toHaveProperty('age__source')
    expect(result.data).not.toHaveProperty('age__hmac')
  })

  it('keeps only the equality term of a TextSearch domain', async () => {
    const result = await typedDynamo.encryptModel(
      { pk: 'user#4', bio: 'a long biography' },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    // TextSearch mints hm + op + bf; only hm is storable as an attribute.
    expect(Object.keys(result.data).sort()).toEqual([
      'bio__hmac',
      'bio__source',
      'pk',
    ])
  })

  it('stores a Json domain as its sv entries plus the KeyHeader', async () => {
    const result = await typedDynamo.encryptModel(
      { pk: 'user#5', meta: { a: 1, b: { c: 'deep' } } },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    // A SteVec document is stored as `{ h, sv }` under __source: the `sv`
    // entries plus the per-document KeyHeader `h` that protect-ffi 0.30 decrypt
    // requires. `v`/`i`/`k` are reconstructed on read, so they are not stored.
    const stored = result.data.meta__source as { h: unknown; sv: unknown[] }
    expect(stored.h).toBeDefined()
    expect(Array.isArray(stored.sv)).toBe(true)
    expect(stored.sv.length).toBeGreaterThan(0)
  })

  it('passes a null column value through without splitting it', async () => {
    // v3 reaches the null check through a different code path than v2:
    // `isStoredEqlPayload` runs before the `k`/`c` gates, so a null must be
    // recognised as a non-payload and passed through verbatim — no
    // `email__source`, no `email__hmac` — with siblings intact.
    const result = await typedDynamo.encryptModel(
      { pk: 'user#null', email: null, role: 'admin' },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(result.data.email).toBeNull()
    expect(result.data).not.toHaveProperty('email__source')
    expect(result.data).not.toHaveProperty('email__hmac')
    expect(result.data.pk).toBe('user#null')
    expect(result.data.role).toBe('admin')

    const decrypted = await typedDynamo.decryptModel(result.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual({
      pk: 'user#null',
      email: null,
      role: 'admin',
    })
  })
})

describe.skipIf(!hasCipherStashCreds)('round trips with a v3 table', () => {
  it('round-trips every domain back to the original item', async () => {
    const original: User = {
      pk: 'user#6',
      email: 'erin@example.com',
      name: 'Erin',
      age: 42,
      bio: 'a long biography',
      meta: { a: 1, b: { c: 'deep' } },
      role: 'admin',
    }

    const encrypted = await typedDynamo.encryptModel(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await typedDynamo.decryptModel(encrypted.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(original)
  })

  it('round-trips the same item through the nominal client', async () => {
    const original: User = {
      pk: 'user#7',
      email: 'frank@example.com',
      age: 7,
      meta: { z: 1 },
    }

    const encrypted = await nominalDynamo.encryptModel(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo.decryptModel(encrypted.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(original)
  })

  it('produces items either client can decrypt — the wire format is the same', async () => {
    const original: User = { pk: 'user#8', email: 'grace@example.com' }

    const encrypted = await typedDynamo.encryptModel(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo.decryptModel(encrypted.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(original)
  })

  /**
   * The one LIVE property. Its pure siblings (`properties.test.ts`) cover the
   * attribute mapping in both directions with a fake ciphertext; this closes the
   * loop over the real thing — every run is a ZeroKMS encrypt + decrypt, so it
   * is capped hard at 5 runs. It is the only check that the split/rebuild
   * survives contact with actual ciphertext across all five domains at once.
   */
  it('property: round-trips arbitrary multi-domain items through ZeroKMS', async () => {
    const jsonLeaf = fc.oneof(fc.string(), fc.integer(), fc.boolean())
    const userArb = fc.record({
      pk: fc.string({ minLength: 1 }),
      email: fc.string(),
      name: fc.string(),
      age: fc.integer(),
      bio: fc.string(),
      meta: fc.dictionary(
        fc.string({ minLength: 1 }),
        fc.oneof(
          jsonLeaf,
          fc.dictionary(fc.string({ minLength: 1 }), jsonLeaf, { maxKeys: 2 }),
        ),
        { minKeys: 1, maxKeys: 3 },
      ),
      role: fc.string(),
    })

    await fc.assert(
      fc.asyncProperty(userArb, async (original) => {
        const encrypted = await typedDynamo.encryptModel(original, users)
        if (encrypted.failure) throw new Error(encrypted.failure.message)

        const decrypted = await typedDynamo.decryptModel(encrypted.data, users)
        if (decrypted.failure) throw new Error(decrypted.failure.message)

        expect(decrypted.data).toEqual(original)
      }),
      // Deliberately small: each run is a real ZeroKMS round trip. The pure
      // properties in `properties.test.ts` cover the attribute mapping
      // exhaustively and for free; this one only needs to establish that the
      // mapping composed with real encryption is identity-preserving over
      // arbitrary items, which a handful of runs does.
      { numRuns: 5 },
    )
  }, 120000)
})

describe.skipIf(!hasCipherStashCreds)('bulk operations with a v3 table', () => {
  it('encrypts and decrypts a batch', async () => {
    const items: User[] = [
      { pk: 'user#9', email: 'a@example.com', name: 'A' },
      { pk: 'user#10', email: 'b@example.com', age: 3 },
    ]

    const encrypted = await typedDynamo.bulkEncryptModels(items, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    expect(encrypted.data).toHaveLength(2)
    for (const item of encrypted.data) {
      expect(item).toHaveProperty('email__source')
      expect(item).toHaveProperty('email__hmac')
    }

    const decrypted = await typedDynamo.bulkDecryptModels(encrypted.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(items)
  })

  it('round-trips a batch through the nominal client', async () => {
    const items: User[] = [
      { pk: 'user#11', email: 'c@example.com' },
      { pk: 'user#12', name: 'D' },
    ]

    const encrypted = await nominalDynamo.bulkEncryptModels(items, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo.bulkDecryptModels(
      encrypted.data,
      users,
    )
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(items)
  })

  it('accepts an empty batch', async () => {
    const encrypted = await typedDynamo.bulkEncryptModels([], users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    expect(encrypted.data).toEqual([])
  })
})

describe.skipIf(!hasCipherStashCreds)(
  'nested attributes with a v3 table',
  () => {
    // EQL v3 has no nested-object *authoring* form — a nested group is a compile
    // error. But a dotted column path is a supported column name, and the model
    // walk in `encryption/helpers/model-helpers.ts` is shared with v2 and matches
    // on dotted paths. So nested DynamoDB attributes work in v3 today, declared
    // flat. This matters for DynamoDB specifically, where items are natively
    // nested documents.
    const nested = encryptedTable('users_v3_nested', {
      'profile.ssn': types.TextEq('profile.ssn'),
      'profile.note': types.Text('profile.note'),
    })

    type NestedUser = {
      pk: string
      profile?: { ssn?: string; note?: string; city?: string }
    }

    let nestedDynamo: EncryptedDynamoDBInstance
    let nestedClient: EncryptionClient

    beforeAll(async () => {
      nestedClient = await Encryption({
        schemas: [nested] as never,
        config: { eqlVersion: 3 },
      })
      nestedDynamo = encryptedDynamoDB({ encryptionClient: nestedClient })
    })

    it('splits nested attributes in place, leaving plaintext siblings alone', async () => {
      const result = await nestedDynamo.encryptModel(
        {
          pk: 'u#1',
          profile: { ssn: '123-45-6789', note: 'hi', city: 'Sydney' },
        },
        nested,
      )

      if (result.failure) throw new Error(result.failure.message)

      const profile = result.data.profile as Record<string, unknown>
      expect(Object.keys(profile).sort()).toEqual([
        'city',
        'note__source',
        'ssn__hmac',
        'ssn__source',
      ])
      expect(profile.city).toBe('Sydney')
    })

    it('round-trips a nested item exactly', async () => {
      const original: NestedUser = {
        pk: 'u#2',
        profile: { ssn: '123-45-6789', note: 'hi', city: 'Sydney' },
      }

      const encrypted = await nestedDynamo.encryptModel(original, nested)
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      const decrypted = await nestedDynamo.decryptModel(encrypted.data, nested)
      if (decrypted.failure) throw new Error(decrypted.failure.message)

      expect(decrypted.data).toEqual(original)
    })

    it('rebuilds the nested identifier from its registered dotted name', async () => {
      const encrypted = await nestedDynamo.encryptModel(
        { pk: 'u#3', profile: { ssn: '123-45-6789' } },
        nested,
      )
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      const rebuilt = toItemWithEqlPayloads(encrypted.data, nested)
      const payload = (rebuilt.profile as Record<string, { i: { c: string } }>)
        .ssn

      expect(payload.i.c).toBe('profile.ssn')
    })

    it('makes a nested equality attribute queryable by __hmac', async () => {
      const ssn = '999-88-7777'

      const stored = await nestedDynamo.encryptModel(
        { pk: 'u#4', profile: { ssn } },
        nested,
      )
      if (stored.failure) throw new Error(stored.failure.message)

      const term = await nestedClient.encryptQuery(ssn, {
        table: nested as never,
        column: nested['profile.ssn'] as never,
      })
      if (term.failure) throw new Error(term.failure.message)

      const profile = stored.data.profile as Record<string, unknown>
      // The query term matches the stored nested `profile.ssn__hmac` — usable in a
      // FilterExpression (a nested attribute can't back a DynamoDB key condition).
      expect((term.data as { hm: string }).hm).toBe(profile.ssn__hmac)
    })

    it('bulk round-trips nested items', async () => {
      const items: NestedUser[] = [
        { pk: 'u#5', profile: { ssn: 'a', city: 'Sydney' } },
        { pk: 'u#6', profile: { note: 'b' } },
      ]

      const encrypted = await nestedDynamo.bulkEncryptModels(items, nested)
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      const decrypted = await nestedDynamo.bulkDecryptModels(
        encrypted.data,
        nested,
      )
      if (decrypted.failure) throw new Error(decrypted.failure.message)

      expect(decrypted.data).toEqual(items)
    })
  },
)

describe.skipIf(!hasCipherStashCreds)(
  'a v3 column whose property differs from its DB name',
  () => {
    // Regression: `encryptedAttrs` was derived from `build().columns`, which for
    // v3 is keyed by DB name, while the encrypted model is keyed by property
    // name. They never matched, so the attribute was never split — no __source,
    // no __hmac, and the payload's `i` block was mangled to `i__source`. Decrypt
    // still round-tripped, so nothing surfaced it; only a key condition that
    // silently matched nothing would have.
    const renamed = encryptedTable('users_v3_renamed', {
      emailAddress: types.TextEq('email_address'),
    })

    let renamedDynamo: EncryptedDynamoDBInstance
    let renamedClient: EncryptionClient

    beforeAll(async () => {
      renamedClient = await Encryption({
        schemas: [renamed] as never,
        config: { eqlVersion: 3 },
      })
      renamedDynamo = encryptedDynamoDB({ encryptionClient: renamedClient })
    })

    it('splits the attribute under its property name, with an __hmac', async () => {
      const result = await renamedDynamo.encryptModel(
        { id: '1', emailAddress: 'a@b.com' },
        renamed,
      )
      if (result.failure) throw new Error(result.failure.message)

      expect(Object.keys(result.data).sort()).toEqual([
        'emailAddress__hmac',
        'emailAddress__source',
        'id',
      ])
      // The payload's identifier block must never leak into an attribute.
      expect(JSON.stringify(result.data)).not.toContain('i__source')
    })

    it('round-trips, and the query term matches the stored __hmac', async () => {
      const original = { id: '2', emailAddress: 'c@d.com' }

      const encrypted = await renamedDynamo.encryptModel(original, renamed)
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      const decrypted = await renamedDynamo.decryptModel(
        encrypted.data,
        renamed,
      )
      if (decrypted.failure) throw new Error(decrypted.failure.message)
      expect(decrypted.data).toEqual(original)

      const term = await renamedClient.encryptQuery('c@d.com', {
        table: renamed as never,
        column: renamed.emailAddress as never,
      })
      if (term.failure) throw new Error(term.failure.message)

      expect((term.data as { hm: string }).hm).toBe(
        (encrypted.data as Record<string, unknown>).emailAddress__hmac,
      )
    })

    it('splits each item under its property name on the bulk path, and round-trips', async () => {
      // Guards the SAME regression on `bulkEncryptModels`: its `encryptedAttrs`
      // must come from `resolveEncryptColumnMap` (property names), not
      // `build().columns` (DB names). With the DB-name form, every item would be
      // stored under `email_address__*` — or not split at all — and no key
      // condition on `emailAddress__hmac` would ever match.
      const items = [
        { id: 'b1', emailAddress: 'e@f.com' },
        { id: 'b2', emailAddress: 'g@h.com' },
      ]

      const encrypted = await renamedDynamo.bulkEncryptModels(items, renamed)
      if (encrypted.failure) throw new Error(encrypted.failure.message)

      expect(encrypted.data).toHaveLength(2)
      for (const item of encrypted.data) {
        const stored = item as Record<string, unknown>
        expect(Object.keys(stored).sort()).toEqual([
          'emailAddress__hmac',
          'emailAddress__source',
          'id',
        ])
        // The DB-name form would have produced these instead of the property-name
        // attributes above.
        expect(stored).not.toHaveProperty('email_address__source')
        expect(stored).not.toHaveProperty('email_address__hmac')
      }

      const decrypted = await renamedDynamo.bulkDecryptModels(
        encrypted.data,
        renamed,
      )
      if (decrypted.failure) throw new Error(decrypted.failure.message)

      expect(decrypted.data).toEqual(items)
    })
  },
)

describe.skipIf(!hasCipherStashCreds)(
  'the __hmac key-condition path with a v3 table',
  () => {
    it('mints, via encryptQuery, the same HMAC the item is stored under', async () => {
      const email = 'heidi@example.com'

      const stored = await typedDynamo.encryptModel(
        { pk: 'user#13', email },
        users,
      )
      if (stored.failure) throw new Error(stored.failure.message)

      const term = await nominalClient.encryptQuery(email, {
        table: users as never,
        column: users.email as never,
      })
      if (term.failure) throw new Error(term.failure.message)

      // `encryptQuery` on a v3 equality domain mints the bare term — `{v, i, hm}`
      // with no ciphertext — so the key condition consumes `hm` directly.
      expect(term.data).not.toHaveProperty('c')
      expect((term.data as { hm: string }).hm).toBe(stored.data.email__hmac)
    })

    it('is deterministic across separate encryptions of the same value', async () => {
      const email = 'ivan@example.com'

      const first = await typedDynamo.encryptModel({ pk: 'a', email }, users)
      const second = await typedDynamo.encryptModel({ pk: 'b', email }, users)
      if (first.failure) throw new Error(first.failure.message)
      if (second.failure) throw new Error(second.failure.message)

      expect(first.data.email__hmac).toBe(second.data.email__hmac)
      expect(first.data.email__source).not.toBe(second.data.email__source)
    })
  },
)

describe.skipIf(!hasCipherStashCreds)('audit metadata with a v3 table', () => {
  const metadata = { sub: 'user-id-123', action: 'v3-port' }

  it('is carried on every operation of the nominal client', async () => {
    const item: User = { pk: 'user#14', email: 'judy@example.com' }

    const encrypted = await nominalDynamo
      .encryptModel(item, users)
      .audit({ metadata })
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo
      .decryptModel(encrypted.data, users)
      .audit({ metadata })
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(item)
  })

  it('is accepted on the typed client, though decrypt cannot carry it', async () => {
    const item: User = { pk: 'user#15', email: 'ken@example.com' }

    const encrypted = await typedDynamo
      .encryptModel(item, users)
      .audit({ metadata })
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    // The typed client's `decryptModel` returns a plain promise with no audit
    // surface. The chain must still resolve correctly — the metadata is simply
    // not forwarded. Use the nominal client if decrypt audit matters.
    const decrypted = await typedDynamo
      .decryptModel(encrypted.data, users)
      .audit({ metadata })
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(item)
  })
})

describe.skipIf(!hasCipherStashCreds)('error handling with a v3 table', () => {
  const unknown = encryptedTable('users_v3_dynamo', {
    nope: types.TextEq('nonexistent_column'),
  })

  it('surfaces the FFI error code for an unregistered column', async () => {
    const result = await typedDynamo.encryptModel({ nope: 'value' }, unknown)

    expect(result.failure).toBeDefined()
    expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
  })

  it('surfaces the FFI ciphertext error code for a malformed __source', async () => {
    const result = await typedDynamo.decryptModel(
      { email__source: 'not-a-ciphertext' },
      users,
    )

    expect(result.failure).toBeDefined()
    expect(result.failure?.name).toBe('EncryptedDynamoDBError')
    // Behaviour difference from v2, and an improvement: in v2 mode this path
    // produced a bare "Unexpected end of input" with no code, so the adapter
    // fell back to DYNAMODB_ENCRYPTION_ERROR (see the v2 suite). v3 rejects it
    // as "Invalid EQL ciphertext" with a real FFI code, which is propagated.
    expect(result.failure?.code).toBe('INVALID_CIPHERTEXT')
    expect(result.failure?.details).toEqual({ context: 'decryptModel' })
  })

  it('surfaces the FFI error code on the bulk encrypt path', async () => {
    const result = await typedDynamo.bulkEncryptModels(
      [{ nope: 'value' }],
      unknown,
    )

    expect(result.failure).toBeDefined()
    expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
  })

  it('surfaces the FFI ciphertext error code on the bulk decrypt path', async () => {
    // The v3 bulk decrypt failure path (resolveDecryptResult +
    // throwPreservingCode against a typed client) is otherwise never exercised
    // end-to-end. Like the single-item v3 path, a malformed __source is rejected
    // as "Invalid EQL ciphertext" with a real FFI code — not the v2 fallback.
    const result = await typedDynamo.bulkDecryptModels(
      [{ email__source: 'not-a-ciphertext' }],
      users,
    )

    expect(result.failure).toBeDefined()
    expect(result.failure?.name).toBe('EncryptedDynamoDBError')
    expect(result.failure?.code).toBe('INVALID_CIPHERTEXT')
    expect(result.failure?.details).toEqual({ context: 'bulkDecryptModels' })
  })

  it('routes v3 failures to the configured errorHandler', async () => {
    const seen: string[] = []
    const instrumented = encryptedDynamoDB({
      encryptionClient: nominalClient,
      options: { errorHandler: (e) => seen.push(e.code) },
    })

    await instrumented.encryptModel({ nope: 'value' }, unknown)

    expect(seen).toEqual(['UNKNOWN_COLUMN'])
  })
})
