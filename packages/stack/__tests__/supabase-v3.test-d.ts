import { describe, expectTypeOf, it } from 'vitest'
import { encryptedTable, type InferPlaintext, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as v2EncryptedTable } from '@/schema'
import {
  type EncryptedSupabaseResponse,
  encryptedSupabaseV3,
  type SupabaseClientLike,
} from '@/supabase'

declare const supabaseClient: SupabaseClientLike

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  amount: types.IntegerOrd('amount'),
  createdAt: types.TimestampOrd('created_at'),
  active: types.Boolean('active'),
})

type UserRow = InferPlaintext<typeof users>

describe('encryptedSupabaseV3 typed surface (with schemas)', () => {
  it('rows carry each column its domain plaintext type', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const { data } = await supabase.from('users').select('id, email, amount')
    expectTypeOf(data![0].email).toEqualTypeOf<string>()
    expectTypeOf(data![0].amount).toEqualTypeOf<number>()
    expectTypeOf(data![0].createdAt).toEqualTypeOf<Date>()
    expectTypeOf(data![0].active).toEqualTypeOf<boolean>()
  })

  it('pins filter value types to the column plaintext', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    builder.eq('email', 'a@b.com')
    builder.gte('amount', 10)
    builder.gte('createdAt', new Date())
    // @ts-expect-error — email is a string column
    builder.eq('email', 42)
    // @ts-expect-error — amount is a number column
    builder.gte('amount', 'ten')
  })

  it('rejects filters on storage-only columns at the type level', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // @ts-expect-error — active is public.boolean (storage only)
    builder.eq('active', true)
    // @ts-expect-error — storage-only column is excluded from filter keys
    builder.is('active', true)
  })

  it('accepts plaintext model values on insert', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    builder.insert({ email: 'a@b.com', amount: 3, createdAt: new Date() })
    // @ts-expect-error — createdAt is a Date column
    builder.insert({ createdAt: 'not-a-date' })
  })

  it('resolves responses to the row type', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    expectTypeOf(
      supabase.from('users').select('id, email'),
    ).resolves.toEqualTypeOf<EncryptedSupabaseResponse<UserRow[]>>()
  })

  it('keeps undeclared tables reachable on the untyped surface (the gradient)', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    // `orders` was introspected but not declared. It MUST still compile, falling
    // through to the untyped `from(table: string)` overload — declaring one
    // table must not make every other table unreachable.
    const builder = supabase.from('orders')
    builder.eq('anything', 1)
    const { data } = await builder.select('id')
    expectTypeOf(data![0]).toEqualTypeOf<Record<string, unknown>>()
  })

  it('rejects a v2 table in schemas', async () => {
    const v2Table = v2EncryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })
    // The directive sits on the call, not the property: no overload accepts a
    // v2 table, so TypeScript reports the failure at the call expression.
    // @ts-expect-error — schemas only accepts v3 tables
    await encryptedSupabaseV3(supabaseClient, {
      schemas: { users: v2Table },
    })
  })
})

describe('encryptedSupabaseV3 untyped surface (no schemas)', () => {
  it('rows default to Record<string, unknown> and from accepts any string', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient)
    const builder = supabase.from('anything')
    const { data } = await builder.select('id, email')
    expectTypeOf(data![0]).toEqualTypeOf<Record<string, unknown>>()
    builder.eq('whatever', 123)
  })

  it('accepts an explicit row generic', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient)
    const builder = supabase.from<{ id: number; email: string }>('users')
    builder.eq('email', 'a@b.com')
    builder.eq('id', 1)
    // @ts-expect-error — not a row key
    builder.eq('missing', 1)
  })

  it('supports a no-arg select(), like supabase-js', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient)
    supabase.from('users').select()
  })
})
