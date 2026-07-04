import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as v2EncryptedTable } from '@/schema'
import {
  type EncryptedQueryBuilder,
  type EncryptedSupabaseResponse,
  encryptedSupabase,
  encryptedSupabaseV3,
  type SupabaseClientLike,
} from '@/supabase'

declare const encryptionClient: EncryptionClient
declare const supabaseClient: SupabaseClientLike

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  amount: types.Int4Ord('amount'),
  createdAt: types.TimestamptzOrd('created_at'),
  active: types.Bool('active'),
})

type UserRow = {
  id: number
  email: string
  amount: number
  createdAt: Date
  active: boolean
  note: string
}

const es = encryptedSupabaseV3({ encryptionClient, supabaseClient })

describe('encryptedSupabaseV3 typing', () => {
  it('defaults rows to exactly InferPlaintext of the table', async () => {
    const builder = es.from('users', users)
    const { data } = await builder.select('id, email, amount')

    // Schema columns carry their domain plaintext types
    expectTypeOf(data![0].email).toEqualTypeOf<string>()
    expectTypeOf(data![0].amount).toEqualTypeOf<number>()
    expectTypeOf(data![0].createdAt).toEqualTypeOf<Date>()
    expectTypeOf(data![0].active).toEqualTypeOf<boolean>()
  })

  it('narrows filter keys in the DEFAULT-Row case (no index-signature widening)', () => {
    const builder = es.from('users', users)

    builder.eq('email', 'a@b.com')
    builder.gte('amount', 10)

    // Storage-only column: excluded even without an explicit Row — the
    // default Row is exactly InferPlaintext, so V3FilterableKeys stays narrow
    // instead of collapsing to string.
    // @ts-expect-error — storage-only column is excluded from filter keys
    builder.eq('active', true)

    // Passthrough (non-schema) columns need an explicit Row to be filterable.
    // @ts-expect-error — not a schema column; pass an explicit Row type
    builder.eq('id', 1)
  })

  it('pins filter value types to the column plaintext with an explicit row type', () => {
    const builder = es.from<typeof users, UserRow>('users', users)

    builder.eq('email', 'a@b.com')
    builder.gte('amount', 10)
    builder.gte('createdAt', new Date())
    builder.eq('id', 1)

    // Wrong value type for a column
    // @ts-expect-error — email is a string column
    builder.eq('email', 42)
    // @ts-expect-error — amount is a number column
    builder.gte('amount', 'ten')
  })

  it('rejects filters on storage-only columns at the type level', () => {
    const builder = es.from<typeof users, UserRow>('users', users)

    // active is eql_v3.bool — storage-only, not filterable
    // @ts-expect-error — storage-only column is excluded from filter keys
    builder.eq('active', true)
    // @ts-expect-error — storage-only column is excluded from filter keys
    builder.is('active', true)
    // match() is FK-narrowed like every other filter method
    builder.match({ email: 'a@b.com', amount: 3 })
    // @ts-expect-error — storage-only column is excluded from match()
    builder.match({ active: true })
  })

  it('accepts plaintext model values on insert', () => {
    const builder = es.from<typeof users, UserRow>('users', users)

    builder.insert({ email: 'a@b.com', amount: 3, createdAt: new Date() })
    builder.insert([{ email: 'a@b.com' }, { note: 'plain' }])

    // @ts-expect-error — createdAt is a Date column
    builder.insert({ createdAt: 'not-a-date' })
  })

  it('resolves responses to the row type', () => {
    const builder = es.from<typeof users, UserRow>('users', users)
    expectTypeOf(builder.select('id, email')).resolves.toEqualTypeOf<
      EncryptedSupabaseResponse<UserRow[]>
    >()
  })

  it('rejects a v2 schema', () => {
    const v2Table = v2EncryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })

    // @ts-expect-error — encryptedSupabaseV3 only accepts v3 tables
    es.from('users', v2Table)
  })
})

describe('encryptedSupabase (v2) typing is unchanged', () => {
  it('keeps the single-generic builder shape', () => {
    const esV2 = encryptedSupabase({ encryptionClient, supabaseClient })
    const v2Table = v2EncryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })

    type V2Row = { id: number; email: string }
    const builder = esV2.from<V2Row>('users', v2Table)
    expectTypeOf(builder).toEqualTypeOf<EncryptedQueryBuilder<V2Row>>()

    builder.eq('email', 'a@b.com')
    builder.eq('id', 1)
    // @ts-expect-error — not a row key
    builder.eq('missing', 1)
  })
})
