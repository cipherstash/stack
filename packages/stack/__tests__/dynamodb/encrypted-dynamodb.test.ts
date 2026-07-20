/**
 * Characterisation tests for `encryptedDynamoDB` against a live client.
 *
 * These pin the CURRENT (EQL v2) end-to-end behaviour of the shipping DynamoDB
 * adapter before the EQL v3 port (#657): what `encryptModel` puts on the wire,
 * that `decryptModel` reverses it exactly, that the `__hmac` attribute an item
 * is stored under is the same value `encryptQuery` mints for a key condition,
 * and how failures surface.
 *
 * There is no DynamoDB in the loop — the adapter never touches the AWS SDK. It
 * maps between EQL payloads and DynamoDB attribute names, so these tests assert
 * on the attribute map that a caller would hand to `PutCommand`.
 *
 * Requires CipherStash credentials (`CS_*`), like the rest of this suite.
 */
import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import type { EncryptedDynamoDBInstance } from '@/dynamodb/types'
import type { EncryptionClient } from '@/encryption'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedField, encryptedTable } from '@/schema'

const users = encryptedTable('users', {
  email: encryptedColumn('email').equality(),
  name: encryptedColumn('name'),
  doc: encryptedColumn('doc').dataType('json').searchableJson(),
  example: {
    protected: encryptedField('example.protected'),
  },
})

type User = {
  pk: string
  email?: string | null
  name?: string | null
  doc?: Record<string, unknown>
  role?: string
  example?: { protected?: string | null; notProtected?: string }
}

/**
 * The attribute map `encryptModel` actually writes for the v2 `users` table.
 *
 * The v2 overload still returns the INPUT model type. Unlike v3, a v2 column
 * does not carry its index configuration in the type, so the `__source` /
 * `__hmac` split cannot be derived the way `EncryptedAttributes` derives it for
 * a v3 table — see the note on `EncryptedDynamoDBInstance.encryptModel`.
 * Naming the wire shape here, rather than widening `User` with an index
 * signature, keeps these assertions honest about what is actually stored.
 */
type StoredUser = {
  pk: string
  role?: string
  email__source?: string
  email__hmac?: string
  name__source?: string
  doc__source?: unknown[]
  example?: { protected__source?: string; notProtected?: string }
}

/** Read a v2 encrypt result as the attribute map it really is. */
const storedAttrs = (item: User): StoredUser => item as StoredUser

let client: EncryptionClient
let dynamo: EncryptedDynamoDBInstance

beforeAll(async () => {
  client = await Encryption({ schemas: [users] })
  dynamo = encryptedDynamoDB({ encryptionClient: client })
})

describe('encryptModel', () => {
  it('splits equality columns into __source and __hmac, and leaves plaintext alone', async () => {
    const result = await dynamo.encryptModel<User>(
      {
        pk: 'user#1',
        email: 'alice@example.com',
        name: 'Alice',
        role: 'admin',
      },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(Object.keys(result.data).sort()).toEqual([
      'email__hmac',
      'email__source',
      'name__source',
      'pk',
      'role',
    ])
    expect(result.data.pk).toBe('user#1')
    expect(result.data.role).toBe('admin')
    expect(typeof storedAttrs(result.data).email__source).toBe('string')
    expect(typeof storedAttrs(result.data).email__hmac).toBe('string')
    // Neither stored attribute leaks the plaintext.
    expect(storedAttrs(result.data).email__source).not.toContain(
      'alice@example.com',
    )
    expect(storedAttrs(result.data).email__hmac).not.toContain(
      'alice@example.com',
    )
  })

  it('gives a non-equality column a __source but no __hmac', async () => {
    const result = await dynamo.encryptModel<User>(
      { pk: 'user#2', name: 'Bob' },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(result.data).toHaveProperty('name__source')
    expect(result.data).not.toHaveProperty('name__hmac')
  })

  it('stores a searchableJson column as a ste_vec array in __source', async () => {
    const result = await dynamo.encryptModel<User>(
      { pk: 'user#3', doc: { a: 1, b: 'two' } },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(Array.isArray(storedAttrs(result.data).doc__source)).toBe(true)
    expect(
      (storedAttrs(result.data).doc__source as unknown[]).length,
    ).toBeGreaterThan(0)
  })

  it('encrypts a nested field in place, keeping siblings plaintext', async () => {
    const result = await dynamo.encryptModel<User>(
      {
        pk: 'user#4',
        example: { protected: 'secret', notProtected: 'public' },
      },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(result.data.example).toEqual({
      protected__source: expect.any(String),
      notProtected: 'public',
    })
  })

  it('passes null through without encrypting it', async () => {
    const result = await dynamo.encryptModel<User>(
      { pk: 'user#5', email: null, name: 'Carol' },
      users,
    )

    if (result.failure) throw new Error(result.failure.message)

    expect(result.data.email).toBeNull()
    expect(result.data).not.toHaveProperty('email__source')
  })

  it('does not mutate the caller’s input object', async () => {
    const input: User = { pk: 'user#6', email: 'dave@example.com' }
    const snapshot = structuredClone(input)

    await dynamo.encryptModel<User>(input, users)

    expect(input).toEqual(snapshot)
  })
})

describe('decryptModel', () => {
  it('round-trips every column shape back to the original item', async () => {
    const original: User = {
      pk: 'user#7',
      email: 'erin@example.com',
      name: 'Erin',
      role: 'admin',
      example: { protected: 'secret', notProtected: 'public' },
    }

    const encrypted = await dynamo.encryptModel<User>(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await dynamo.decryptModel<User>(encrypted.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(original)
  })

  it('round-trips a searchableJson document', async () => {
    const original: User = { pk: 'user#8', doc: { a: 1, b: 'two' } }

    const encrypted = await dynamo.encryptModel<User>(original, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await dynamo.decryptModel<User>(encrypted.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(original)
  })

  it('tolerates the __hmac attribute being present on the stored item', async () => {
    const encrypted = await dynamo.encryptModel<User>(
      { pk: 'user#9', email: 'frank@example.com' },
      users,
    )
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    expect(encrypted.data).toHaveProperty('email__hmac')

    const decrypted = await dynamo.decryptModel<User>(encrypted.data, users)
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data.email).toBe('frank@example.com')
  })
})

describe('bulk operations', () => {
  it('encrypts and decrypts a batch, preserving order and per-item shape', async () => {
    const items: User[] = [
      { pk: 'user#10', email: 'a@example.com', name: 'A' },
      { pk: 'user#11', email: 'b@example.com', name: 'B', role: 'admin' },
    ]

    const encrypted = await dynamo.bulkEncryptModels<User>(items, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    expect(encrypted.data).toHaveLength(2)
    for (const item of encrypted.data) {
      expect(item).toHaveProperty('email__source')
      expect(item).toHaveProperty('email__hmac')
    }

    const decrypted = await dynamo.bulkDecryptModels<User>(
      encrypted.data,
      users,
    )
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(items)
  })

  it('handles heterogeneous items in one batch', async () => {
    const items: User[] = [
      { pk: 'user#12', email: 'c@example.com' },
      { pk: 'user#13', name: 'D', example: { protected: 'secret' } },
    ]

    const encrypted = await dynamo.bulkEncryptModels<User>(items, users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    const decrypted = await dynamo.bulkDecryptModels<User>(
      encrypted.data,
      users,
    )
    if (decrypted.failure) throw new Error(decrypted.failure.message)

    expect(decrypted.data).toEqual(items)
  })

  it('accepts an empty batch', async () => {
    const encrypted = await dynamo.bulkEncryptModels<User>([], users)
    if (encrypted.failure) throw new Error(encrypted.failure.message)

    expect(encrypted.data).toEqual([])
  })
})

describe('the __hmac key-condition path', () => {
  it('mints, via encryptQuery, the same HMAC the item is stored under', async () => {
    const email = 'grace@example.com'

    const stored = await dynamo.encryptModel<User>(
      { pk: 'user#14', email },
      users,
    )
    if (stored.failure) throw new Error(stored.failure.message)

    const term = await client.encryptQuery(email, {
      table: users,
      column: users.email,
      queryType: 'equality',
    })
    if (term.failure) throw new Error(term.failure.message)

    // This equality is the whole DynamoDB query story: a caller puts
    // `term.data.hm` into `KeyConditionExpression: "email__hmac = :e"` and it
    // matches the attribute written at encrypt time.
    expect((term.data as { hm: string }).hm).toBe(
      storedAttrs(stored.data).email__hmac,
    )
  })

  it('mints a different HMAC for a different plaintext', async () => {
    const term = await client.encryptQuery('someone-else@example.com', {
      table: users,
      column: users.email,
      queryType: 'equality',
    })
    if (term.failure) throw new Error(term.failure.message)

    const stored = await dynamo.encryptModel<User>(
      { pk: 'user#15', email: 'grace@example.com' },
      users,
    )
    if (stored.failure) throw new Error(stored.failure.message)

    expect((term.data as { hm: string }).hm).not.toBe(
      storedAttrs(stored.data).email__hmac,
    )
  })

  it('is deterministic across separate encryptions of the same value', async () => {
    const email = 'heidi@example.com'

    const first = await dynamo.encryptModel<User>({ pk: 'a', email }, users)
    const second = await dynamo.encryptModel<User>({ pk: 'b', email }, users)
    if (first.failure) throw new Error(first.failure.message)
    if (second.failure) throw new Error(second.failure.message)

    expect(storedAttrs(first.data).email__hmac).toBe(
      storedAttrs(second.data).email__hmac,
    )
    // ...while the ciphertext itself is not deterministic.
    expect(storedAttrs(first.data).email__source).not.toBe(
      storedAttrs(second.data).email__source,
    )
  })
})

describe('audit metadata', () => {
  it('is accepted on every operation without changing the result', async () => {
    const metadata = { sub: 'user-id-123', action: 'characterisation' }
    const item: User = {
      pk: 'user#16',
      email: 'ivan@example.com',
      name: 'Ivan',
    }

    const encrypted = await dynamo
      .encryptModel<User>(item, users)
      .audit({ metadata })
    if (encrypted.failure) throw new Error(encrypted.failure.message)
    expect(encrypted.data).toHaveProperty('email__hmac')

    const decrypted = await dynamo
      .decryptModel<User>(encrypted.data, users)
      .audit({ metadata })
    if (decrypted.failure) throw new Error(decrypted.failure.message)
    expect(decrypted.data).toEqual(item)

    const bulkEncrypted = await dynamo
      .bulkEncryptModels<User>([item], users)
      .audit({ metadata })
    if (bulkEncrypted.failure) throw new Error(bulkEncrypted.failure.message)

    const bulkDecrypted = await dynamo
      .bulkDecryptModels<User>(bulkEncrypted.data, users)
      .audit({ metadata })
    if (bulkDecrypted.failure) throw new Error(bulkDecrypted.failure.message)
    expect(bulkDecrypted.data).toEqual([item])
  })

  it('returns the operation itself so .audit() can be chained before awaiting', () => {
    const operation = dynamo.encryptModel<User>({ pk: 'x' }, users)

    expect(operation.audit({ metadata: {} })).toBe(operation)
  })
})

describe('error handling', () => {
  const unknownColumn = encryptedTable('users', {
    nope: encryptedColumn('nonexistent_column'),
  })

  it('surfaces the FFI error code when encrypting an unregistered column', async () => {
    const result = await dynamo.encryptModel(
      { nope: 'value' },
      // Not among the client's schemas — the FFI rejects the column.
      unknownColumn,
    )

    expect(result.failure).toBeDefined()
    expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
  })

  it('surfaces the FFI error code on the bulk encrypt path', async () => {
    const result = await dynamo.bulkEncryptModels(
      [{ nope: 'value' }],
      unknownColumn,
    )

    expect(result.failure).toBeDefined()
    expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
  })

  it('fails with a DynamoDB error code when __source is not a ciphertext', async () => {
    const result = await dynamo.decryptModel(
      { email__source: 'not-a-ciphertext' },
      users,
    )

    expect(result.failure).toBeDefined()
    expect(result.failure?.name).toBe('EncryptedDynamoDBError')
    // No FFI code on this path, so the adapter's own fallback code is used.
    expect(result.failure?.code).toBe('DYNAMODB_ENCRYPTION_ERROR')
    expect(result.failure?.details).toEqual({ context: 'decryptModel' })
  })

  it('fails on the bulk decrypt path for malformed ciphertext', async () => {
    const result = await dynamo.bulkDecryptModels(
      [{ email__source: 'not-a-ciphertext' }],
      users,
    )

    expect(result.failure).toBeDefined()
    expect(result.failure?.code).toBe('DYNAMODB_ENCRYPTION_ERROR')
    expect(result.failure?.details).toEqual({ context: 'bulkDecryptModels' })
  })

  it('routes failures to the configured errorHandler', async () => {
    const seen: { code: string; message: string }[] = []
    const instrumented = encryptedDynamoDB({
      encryptionClient: client,
      options: {
        errorHandler: (e) => seen.push({ code: e.code, message: e.message }),
      },
    })

    await instrumented.encryptModel({ nope: 'value' }, unknownColumn)

    expect(seen).toHaveLength(1)
    expect(seen[0]?.code).toBe('UNKNOWN_COLUMN')
  })
})
