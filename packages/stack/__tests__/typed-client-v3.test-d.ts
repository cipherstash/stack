import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
// Everything comes from the single `@cipherstash/stack/v3` surface (re-exported
// from src/encryption/v3.ts), exercising the re-export at the same time.
import {
  encryptedInt4OrdColumn,
  encryptedInt8Column,
  encryptedTable,
  encryptedTextColumn,
  encryptedTextEqColumn,
  encryptedTextSearchColumn,
  encryptedTimestamptzOrdColumn,
  typedClient,
  type V3DecryptedModel,
  type V3EncryptedModel,
} from '@/encryption/v3'
import type { Encrypted } from '@/types'

// A v3 table mixing every relevant capability tier:
const users = encryptedTable('users', {
  email: encryptedTextEqColumn('email'), // equality only
  bio: encryptedTextSearchColumn('bio'), // equality + order + free-text
  note: encryptedTextColumn('note'), // storage only (not queryable)
  createdAt: encryptedTimestamptzOrdColumn('created_at'), // equality + order
  id64: encryptedInt8Column('id64'), // storage-only bigint
})

// A second registered table whose `weight` domain (int4_ord) is NOT present in
// `users`, so borrowing it is a genuine cross-table type error.
const other = encryptedTable('other', {
  weight: encryptedInt4OrdColumn('weight'),
})

const client = typedClient({} as EncryptionClient, users, other)

describe('typed v3 client — encrypt plaintext is pinned to the column domain', () => {
  it('accepts the matching plaintext type per domain', () => {
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: users,
      column: users.email,
    })
    expectTypeOf(client.encrypt).toBeCallableWith(1n, {
      table: users,
      column: users.id64,
    })
    expectTypeOf(client.encrypt).toBeCallableWith(new Date(), {
      table: users,
      column: users.createdAt,
    })
  })

  it('rejects a wrong-typed plaintext', () => {
    client.encrypt(
      // @ts-expect-error - number is not valid plaintext for a text column
      123,
      { table: users, column: users.email },
    )
  })
})

describe('typed v3 client — encryptQuery constrains queryType to capabilities', () => {
  it('accepts capability-matched query types', () => {
    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: users,
      column: users.email,
      queryType: 'equality',
    })
    expectTypeOf(client.encryptQuery).toBeCallableWith(new Date(), {
      table: users,
      column: users.createdAt,
      queryType: 'orderAndRange',
    })
    // text_search supports all three
    expectTypeOf(client.encryptQuery).toBeCallableWith('needle', {
      table: users,
      column: users.bio,
      queryType: 'freeTextSearch',
    })
  })

  it('rejects a query type the column does not support', () => {
    client.encryptQuery('alice@example.com', {
      table: users,
      column: users.email, // equality only
      // @ts-expect-error - text_eq column does not support 'orderAndRange'
      queryType: 'orderAndRange',
    })
    client.encryptQuery(new Date(), {
      table: users,
      column: users.createdAt, // equality + order, no free-text
      // @ts-expect-error - timestamptz_ord column does not support 'freeTextSearch'
      queryType: 'freeTextSearch',
    })
  })

  it('rejects a storage-only column on the query path', () => {
    client.encryptQuery('x', {
      table: users,
      // @ts-expect-error - storage-only text column is not queryable
      column: users.note,
    })
  })
})

describe('typed v3 client — model encrypt validates schema fields', () => {
  it('accepts a model whose schema fields match and allows passthrough fields', () => {
    expectTypeOf(client.encryptModel).toBeCallableWith(
      { id: 'u1', email: 'a@b.com', createdAt: new Date() },
      users,
    )
  })

  it('rejects a wrong-typed schema field', () => {
    client.encryptModel(
      {
        id: 'u1',
        // @ts-expect-error - email expects string, got number
        email: 123,
      },
      users,
    )
  })

  it('maps schema columns to Encrypted and preserves passthrough + nullability', () => {
    // Passthrough `id` stays string; schema `email` becomes Encrypted.
    expectTypeOf<
      V3EncryptedModel<typeof users, { id: string; email: string }>
    >().toEqualTypeOf<{ id: string; email: Encrypted }>()

    // Nullable schema field → Encrypted | null.
    expectTypeOf<
      V3EncryptedModel<typeof users, { id: string; email: string | null }>
    >().toEqualTypeOf<{ id: string; email: Encrypted | null }>()
  })
})

describe('typed v3 client — model decrypt yields precise plaintext', () => {
  it('reconstructs schema columns to their plaintext type regardless of the input field type', () => {
    // Input is the encrypted row; output pins each schema column to its plaintext
    // type (Date for timestamptz, bigint for int8, string for text).
    expectTypeOf<
      V3DecryptedModel<
        typeof users,
        { id: string; email: Encrypted; createdAt: Encrypted; id64: Encrypted }
      >
    >().toEqualTypeOf<{
      id: string
      email: string
      createdAt: Date
      id64: bigint
    }>()
  })

  it('decryptModel is callable with an encrypted row and the table', () => {
    expectTypeOf(client.decryptModel).toBeCallableWith(
      { id: 'u1', email: {} as Encrypted },
      users,
    )
  })
})

describe('typed v3 client — soundness', () => {
  it('rejects a hand-rolled structural table (no brand / private field)', () => {
    const fakeTable = {
      tableName: 'users',
      build: () => ({ tableName: 'users', columns: {} }),
    }
    client.encrypt('x', {
      // @ts-expect-error - a structural object is not a registered branded v3 table
      table: fakeTable,
      column: users.email,
    })
  })

  it('rejects a column whose domain is not present in the table', () => {
    // Plaintext is a string (valid for every `users` column domain) so the only
    // error is the column itself failing the `ColumnsOf<typeof users>` constraint.
    client.encrypt('x', {
      table: users,
      // @ts-expect-error - int4_ord column from `other` is not in ColumnsOf<typeof users>
      column: other.weight,
    })
  })
})
