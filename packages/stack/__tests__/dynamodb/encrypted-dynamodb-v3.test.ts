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
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import type { EncryptedDynamoDBInstance } from '@/dynamodb/types'
import type { EncryptionClient } from '@/encryption'
import { EncryptionV3 } from '@/encryption/v3'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'

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
  meta?: Record<string, unknown>
  role?: string
}

/** The typed client from `EncryptionV3` — the documented v3 entry point. */
let typedDynamo: EncryptedDynamoDBInstance
/** The nominal chainable client, forced into v3 mode. */
let nominalClient: EncryptionClient
let nominalDynamo: EncryptedDynamoDBInstance

beforeAll(async () => {
  const typedClient = await EncryptionV3({ schemas: [users] })
  typedDynamo = encryptedDynamoDB({ encryptionClient: typedClient })

  nominalClient = await Encryption({
    schemas: [users] as never,
    config: { eqlVersion: 3 },
  })
  nominalDynamo = encryptedDynamoDB({ encryptionClient: nominalClient })
})

describe('encryptModel with a v3 table', () => {
  it('splits an equality domain into __source and __hmac', async () => {
    const result = await typedDynamo.encryptModel<User>(
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
    const result = await typedDynamo.encryptModel<User>(
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
    const result = await typedDynamo.encryptModel<User>(
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
    const result = await typedDynamo.encryptModel<User>(
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

  it('stores a Json domain as a ste_vec array', async () => {
    const result = await typedDynamo.encryptModel<User>(
      { pk: 'user#5', meta: { a: 1, b: { c: 'deep' } } },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(Array.isArray(result.data.meta__source)).toBe(true)
    expect((result.data.meta__source as unknown[]).length).toBeGreaterThan(0)
  })
})

describe('round trips with a v3 table', () => {
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

    const encrypted = await typedDynamo.encryptModel<User>(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await typedDynamo.decryptModel<User>(
      encrypted.data,
      users,
    )
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

    const encrypted = await nominalDynamo.encryptModel<User>(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo.decryptModel<User>(
      encrypted.data,
      users,
    )
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(original)
  })

  it('produces items either client can decrypt — the wire format is the same', async () => {
    const original: User = { pk: 'user#8', email: 'grace@example.com' }

    const encrypted = await typedDynamo.encryptModel<User>(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo.decryptModel<User>(
      encrypted.data,
      users,
    )
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(original)
  })
})

describe('bulk operations with a v3 table', () => {
  it('encrypts and decrypts a batch', async () => {
    const items: User[] = [
      { pk: 'user#9', email: 'a@example.com', name: 'A' },
      { pk: 'user#10', email: 'b@example.com', age: 3 },
    ]

    const encrypted = await typedDynamo.bulkEncryptModels<User>(items, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    expect(encrypted.data).toHaveLength(2)
    for (const item of encrypted.data) {
      expect(item).toHaveProperty('email__source')
      expect(item).toHaveProperty('email__hmac')
    }

    const decrypted = await typedDynamo.bulkDecryptModels<User>(
      encrypted.data,
      users,
    )
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(items)
  })

  it('round-trips a batch through the nominal client', async () => {
    const items: User[] = [
      { pk: 'user#11', email: 'c@example.com' },
      { pk: 'user#12', name: 'D' },
    ]

    const encrypted = await nominalDynamo.bulkEncryptModels<User>(items, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo.bulkDecryptModels<User>(
      encrypted.data,
      users,
    )
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(items)
  })
})

describe('the __hmac key-condition path with a v3 table', () => {
  it('mints, via encryptQuery, the same HMAC the item is stored under', async () => {
    const email = 'heidi@example.com'

    const stored = await typedDynamo.encryptModel<User>(
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

    const first = await typedDynamo.encryptModel<User>(
      { pk: 'a', email },
      users,
    )
    const second = await typedDynamo.encryptModel<User>(
      { pk: 'b', email },
      users,
    )
    if (first.failure) throw new Error(first.failure.message)
    if (second.failure) throw new Error(second.failure.message)

    expect(first.data.email__hmac).toBe(second.data.email__hmac)
    expect(first.data.email__source).not.toBe(second.data.email__source)
  })
})

describe('audit metadata with a v3 table', () => {
  const metadata = { sub: 'user-id-123', action: 'v3-port' }

  it('is carried on every operation of the nominal client', async () => {
    const item: User = { pk: 'user#14', email: 'judy@example.com' }

    const encrypted = await nominalDynamo
      .encryptModel<User>(item, users)
      .audit({ metadata })
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await nominalDynamo
      .decryptModel<User>(encrypted.data, users)
      .audit({ metadata })
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(item)
  })

  it('is accepted on the typed client, though decrypt cannot carry it', async () => {
    const item: User = { pk: 'user#15', email: 'ken@example.com' }

    const encrypted = await typedDynamo
      .encryptModel<User>(item, users)
      .audit({ metadata })
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    // The typed client's `decryptModel` returns a plain promise with no audit
    // surface. The chain must still resolve correctly — the metadata is simply
    // not forwarded. Use the nominal client if decrypt audit matters.
    const decrypted = await typedDynamo
      .decryptModel<User>(encrypted.data, users)
      .audit({ metadata })
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(item)
  })
})

describe('error handling with a v3 table', () => {
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
