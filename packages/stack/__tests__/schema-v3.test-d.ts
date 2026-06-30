import { describe, expectTypeOf, it } from 'vitest'
import { Encryption, EncryptionClient } from '@/encryption'
// v2 column builders — used to prove the v3 table type rejects a v2 column and
// to assert v2 backward-compat against the widened client types.
import {
  encryptedColumn,
  encryptedField,
  encryptedTable as v2EncryptedTable,
} from '@/schema'
import type {
  EncryptedTextSearchColumn,
  InferEncrypted,
  InferPlaintext,
} from '@/schema/v3'
import { encryptedTable, encryptedTextSearchColumn } from '@/schema/v3'
import type { Encrypted } from '@/types'

describe('eql_v3 schema type inference', () => {
  it('encryptedTextSearchColumn returns an EncryptedTextSearchColumn', () => {
    const col = encryptedTextSearchColumn('email')
    expectTypeOf(col).toEqualTypeOf<EncryptedTextSearchColumn>()
  })

  it('encryptedTable exposes column builders as typed properties', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    expectTypeOf(users.email).toEqualTypeOf<EncryptedTextSearchColumn>()
    expectTypeOf(users.tableName).toBeString()
  })

  it('rejects a v2 EncryptedColumn in a v3 table (nominal private-field mismatch)', () => {
    encryptedTable('users', {
      // @ts-expect-error - a v2 EncryptedColumn is not an EncryptedTextSearchColumn
      email: encryptedColumn('email'),
    })
  })

  it('InferPlaintext maps each column to string', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
      name: encryptedTextSearchColumn('name'),
    })
    type Plaintext = InferPlaintext<typeof users>
    expectTypeOf<Plaintext>().toEqualTypeOf<{ email: string; name: string }>()
  })

  it('InferEncrypted maps each column to Encrypted', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    type Enc = InferEncrypted<typeof users>
    expectTypeOf<Enc>().toEqualTypeOf<{ email: Encrypted }>()
  })
})

describe('eql_v3 client integration (type-level acceptance)', () => {
  const v3users = encryptedTable('users', {
    email: encryptedTextSearchColumn('email'),
  })

  it('Encryption accepts a v3 schema', () => {
    expectTypeOf(Encryption).toBeCallableWith({ schemas: [v3users] })
  })

  it('encrypt accepts a v3 table + column', () => {
    const client = {} as EncryptionClient
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: v3users,
      column: v3users.email,
    })
  })

  it('encryptQuery accepts a v3 table + column', () => {
    const client = {} as EncryptionClient
    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: v3users,
      column: v3users.email,
    })
  })

  it('decrypt accepts an Encrypted value (round-trip target type; schema-independent)', () => {
    const client = {} as EncryptionClient
    expectTypeOf(client.decrypt).toBeCallableWith({} as Encrypted)
  })

  it('BACKWARD COMPAT: v2 tables/columns still satisfy the widened types', () => {
    const v2users = v2EncryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })
    expectTypeOf(Encryption).toBeCallableWith({ schemas: [v2users] })
    const client = {} as EncryptionClient
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: v2users,
      column: v2users.email,
    })
    // a v2 EncryptedColumn is STILL queryable (nominal arm of BuildableQueryColumn)
    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: v2users,
      column: v2users.email,
    })
  })

  it('a non-queryable v2 EncryptedField is encryptable but NOT queryable', () => {
    const v2usersWithField = v2EncryptedTable('users', {
      profile: { email: encryptedField('email') },
    })
    const client = {} as EncryptionClient

    // POSITIVE: a field IS encryptable (storage path = BuildableColumn)
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: v2usersWithField,
      column: v2usersWithField.profile.email,
    })

    // NEGATIVE: a field is NOT queryable. The query path uses
    // BuildableQueryColumn, which excludes EncryptedField (no indexes). If the
    // query path were instead widened to BuildableColumn (the rejected
    // Batch-2/3 design), this call would compile and only fail at runtime with
    // "no indexes configured" — so this test guards against that re-widening.
    //
    // The mismatch is a DEEP object-literal property error, so tsc reports it on
    // the `column:` line — the `@ts-expect-error` MUST sit directly above that
    // line (not above the call), or you get TS2578 "unused directive" + the real
    // error leaking. (Mirror of Task 4's v2-column-rejected test placement.)
    client.encryptQuery('alice@example.com', {
      table: v2usersWithField,
      // @ts-expect-error - EncryptedField is not assignable to BuildableQueryColumn
      column: v2usersWithField.profile.email,
    })
  })
})
