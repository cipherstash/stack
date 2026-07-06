import { describe, expectTypeOf, it } from 'vitest'
import { Encryption, type EncryptionClient } from '@/encryption'
import type {
  EncryptedTextSearchColumn,
  InferEncrypted,
  InferPlaintext,
  QueryTypesForColumn,
} from '@/eql/v3'
import { encrypted, encryptedTable, types } from '@/eql/v3'
// v2 column builders — used to prove the v3 table type rejects a v2 column and
// to assert v2 backward-compat against the widened client types.
import {
  encryptedColumn,
  encryptedField,
  encryptedTable as v2EncryptedTable,
} from '@/schema'
import type { Encrypted } from '@/types'

describe('eql_v3 schema type inference', () => {
  it('types.TextSearch returns an EncryptedTextSearchColumn', () => {
    const col = types.TextSearch('email')
    expectTypeOf(col).toEqualTypeOf<EncryptedTextSearchColumn>()
  })

  it('encryptedTable exposes column builders as typed properties', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
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
      email: types.TextSearch('email'),
      name: types.TextSearch('name'),
    })
    type Plaintext = InferPlaintext<typeof users>
    expectTypeOf<Plaintext>().toEqualTypeOf<{ email: string; name: string }>()
  })

  it('InferEncrypted maps each column to Encrypted', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    type Enc = InferEncrypted<typeof users>
    expectTypeOf<Enc>().toEqualTypeOf<{ email: Encrypted }>()
  })

  it('InferPlaintext maps v3 concrete domains to plaintext TypeScript types', () => {
    const metrics = encryptedTable('metrics', {
      name: types.Text('name'),
      age: types.Int4('age'),
      active: types.Bool('active'),
      createdAt: types.Timestamptz('created_at'),
      score: types.Float8('score'),
    })

    type Plaintext = InferPlaintext<typeof metrics>

    expectTypeOf<Plaintext>().toEqualTypeOf<{
      name: string
      age: number
      active: boolean
      createdAt: Date
      score: number
    }>()
  })

  it('v3 domain classes remain nominal by literal domain definition', () => {
    const date = types.Date('created_on')
    const bool = types.Bool('active')

    expectTypeOf(date).not.toEqualTypeOf<typeof bool>()

    // @ts-expect-error - storage-only bool is not assignable to storage-only date
    const invalid: typeof date = bool
    void invalid
  })

  it('encrypted fluent namespace preserves plaintext and query inference', () => {
    const users = encryptedTable('users', {
      email: encrypted.text('email').equality().freeTextSearch(),
      age: encrypted.integer('age').equality(),
      createdAt: encrypted.timestamp('created_at').orderAndRange(),
      active: encrypted.boolean('active'),
    })

    expectTypeOf<InferPlaintext<typeof users>>().toEqualTypeOf<{
      email: string
      age: number
      createdAt: Date
      active: boolean
    }>()
    expectTypeOf<QueryTypesForColumn<typeof users.email>>().toEqualTypeOf<
      'equality' | 'orderAndRange' | 'freeTextSearch'
    >()
    expectTypeOf<
      QueryTypesForColumn<typeof users.age>
    >().toEqualTypeOf<'equality'>()
    expectTypeOf<QueryTypesForColumn<typeof users.createdAt>>().toEqualTypeOf<
      'equality' | 'orderAndRange'
    >()
    expectTypeOf<
      QueryTypesForColumn<typeof users.active>
    >().toEqualTypeOf<never>()
  })

  it('encrypted fluent namespace rejects unsupported capability chains', () => {
    // @ts-expect-error - integer columns do not support free-text search
    encrypted.integer('age').freeTextSearch()

    // @ts-expect-error - date columns do not support free-text search
    encrypted.date('created_on').freeTextSearch()

    // @ts-expect-error - boolean has no query-capability fluent methods
    encrypted.boolean('active').equality()
  })
})

describe('eql_v3 client integration (type-level acceptance)', () => {
  const v3users = encryptedTable('users', {
    email: types.TextSearch('email'),
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

  it('encryptQuery accepts queryable v3 columns with explicit capability metadata', () => {
    const users = encryptedTable('users', {
      emailEq: types.TextEq('email_eq'),
      emailMatch: types.TextMatch('email_match'),
      emailSearch: types.TextSearch('email_search'),
      createdAt: types.TimestamptzOrd('created_at'),
    })
    const client = {} as EncryptionClient

    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: users,
      column: users.emailEq,
    })
    expectTypeOf(client.encryptQuery).toBeCallableWith('ali', {
      table: users,
      column: users.emailMatch,
      queryType: 'freeTextSearch',
    })
    expectTypeOf(client.encryptQuery).toBeCallableWith(new Date(), {
      table: users,
      column: users.createdAt,
      queryType: 'orderAndRange',
    })
    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: users,
      column: users.emailSearch,
      queryType: 'equality',
    })
  })

  it('encryptQuery rejects storage-only v3 columns at compile time', () => {
    const users = encryptedTable('users', {
      email: types.Text('email'),
      active: types.Bool('active'),
    })
    const client = {} as EncryptionClient

    client.encryptQuery('alice@example.com', {
      table: users,
      // @ts-expect-error - storage-only v3 text column is not queryable
      column: users.email,
    })

    client.encryptQuery(true, {
      table: users,
      // @ts-expect-error - storage-only v3 bool column is not queryable
      column: users.active,
    })
  })
})

describe('eql_v3 model encryption inference', () => {
  it('encryptModel and bulkEncryptModels infer encrypted fields from v3 tables', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
      active: types.Bool('active'),
    })
    const client = {} as EncryptionClient

    const encryptedOne = client.encryptModel(
      { id: 'u1', email: 'alice@example.com', active: true, untouched: 42 },
      users,
    )
    expectTypeOf(encryptedOne).toEqualTypeOf<
      import('@/encryption').EncryptModelOperation<{
        id: string
        email: Encrypted
        active: Encrypted
        untouched: number
      }>
    >()

    const encryptedMany = client.bulkEncryptModels(
      [{ id: 'u1', email: 'alice@example.com', active: true }],
      users,
    )
    expectTypeOf(encryptedMany).toEqualTypeOf<
      import('@/encryption').BulkEncryptModelsOperation<{
        id: string
        email: Encrypted
        active: Encrypted
      }>
    >()
  })

  it('v3 encryptModel preserves unrelated and nullable fields', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    const client = {} as EncryptionClient

    const encrypted = client.encryptModel(
      { id: 'u1', email: null as string | null, untouched: 42 },
      users,
    )

    expectTypeOf(encrypted).toEqualTypeOf<
      import('@/encryption').EncryptModelOperation<{
        id: string
        email: Encrypted | null
        untouched: number
      }>
    >()
  })

  it('encryptModel degrades gracefully for a bare BuildableTable-typed value (no brand)', () => {
    // A table passed through a value/param annotated as the structural
    // `BuildableTable` (no `_columnType` brand) cannot recover its literal
    // column keys. It must degrade to the model unchanged — NOT mark every
    // field `Encrypted`. Regression guard: `keyof BuildableTableColumns<...>`
    // must resolve to `never` here, not `keyof never` (= string|number|symbol),
    // which would wrongly encrypt all fields including `id` and `untouched`.
    const usersConcrete = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    const table: import('@/types').BuildableTable = usersConcrete
    const client = {} as EncryptionClient

    const encrypted = client.encryptModel(
      { id: 'u1', email: 'alice@example.com', untouched: 42 },
      table,
    )
    expectTypeOf(encrypted).toEqualTypeOf<
      import('@/encryption').EncryptModelOperation<{
        id: string
        email: string
        untouched: number
      }>
    >()
  })

  it('model inference keys off the property name, not the DB column name (aliased columns)', () => {
    // The column's DB name ('created_at') differs from the object property name
    // ('occurredAt'). Model inference keys off the PROPERTY name, so `occurredAt`
    // must become `Encrypted` while unrelated fields are preserved verbatim.
    const events = encryptedTable('events', {
      occurredAt: types.Timestamptz('created_at'),
    })
    const client = {} as EncryptionClient

    const encryptedOne = client.encryptModel(
      { id: 'e1', occurredAt: new Date(), label: 'signup' },
      events,
    )
    expectTypeOf(encryptedOne).toEqualTypeOf<
      import('@/encryption').EncryptModelOperation<{
        id: string
        occurredAt: Encrypted
        label: string
      }>
    >()

    const encryptedMany = client.bulkEncryptModels(
      [{ id: 'e1', occurredAt: new Date(), label: 'signup' }],
      events,
    )
    expectTypeOf(encryptedMany).toEqualTypeOf<
      import('@/encryption').BulkEncryptModelsOperation<{
        id: string
        occurredAt: Encrypted
        label: string
      }>
    >()
  })

  it('v2 encryptModel inference still preserves non-schema fields after widening', () => {
    const users = v2EncryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })
    const client = {} as EncryptionClient

    const encrypted = client.encryptModel(
      { id: 'u1', email: 'alice@example.com', age: 30 },
      users,
    )

    expectTypeOf(encrypted).toEqualTypeOf<
      import('@/encryption').EncryptModelOperation<{
        id: string
        email: Encrypted
        age: number
      }>
    >()
  })
})
