import { describe, expectTypeOf, it } from 'vitest'
import { encryptedTable, type InferPlaintext, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as v2EncryptedTable } from '@/schema'
import {
  type EncryptedSupabaseResponse,
  encryptedSupabase,
  encryptedSupabaseV3,
  type SupabaseClientLike,
} from '@/supabase'

declare const supabaseClient: SupabaseClientLike

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  amount: types.IntegerOrd('amount'),
  createdAt: types.TimestampOrd('created_at'),
  active: types.Boolean('active'),
  nickname: types.TextEq('nickname'),
  bio: types.TextMatch('bio'),
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

  it('rejects order() on every encrypted column at the type level', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // No btree opclass exists on any EQL v3 domain, so `ORDER BY col` sorts the
    // ciphertext envelope. This holds for the ORE-capable domains too — which is
    // the whole point: those are the ones where the wrongness is silent.
    // @ts-expect-error — timestamp_ord: ORDER BY sorts ciphertext
    builder.order('createdAt')
    // @ts-expect-error — integer_ord: ORDER BY sorts ciphertext
    builder.order('amount', { ascending: false })
    // @ts-expect-error — active is public.boolean: storage only
    builder.order('active')
  })

  it('still allows order() on a plaintext row key', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    // `note` is not a declared column, so it is a plaintext passthrough.
    const builder = supabase.from<{ note: string }>('users')
    builder.order('note')
  })

  it('narrows contains() to freeTextSearch-capable columns', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // public.text_search — equality + orderAndRange + freeTextSearch
    builder.contains('email', 'ada')
    // public.text_match — freeTextSearch only
    builder.contains('bio', 'ada')
    // @ts-expect-error — nickname is public.text_eq: no match index
    builder.contains('nickname', 'ada')
    // @ts-expect-error — amount is public.integer_ord: no match index
    builder.contains('amount', 'ada')
    // @ts-expect-error — active is public.boolean (storage only)
    builder.contains('active', 'ada')
  })

  it('does not expose like/ilike on the v3 builder, at any chain depth', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // @ts-expect-error — v3 free-text search is token containment: use contains()
    builder.like('email', '%ada%')
    // @ts-expect-error — v3 free-text search is token containment: use contains()
    builder.ilike('email', '%ada%')
    // The chain must not launder the removal back in via a widened return type.
    // @ts-expect-error — use contains()
    builder.select('id').eq('email', 'a@b.com').like('email', '%ada%')
    // contains() survives the chain.
    builder.select('id').eq('email', 'a@b.com').contains('email', 'ada')
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

  it('exposes contains and not like/ilike, exactly as the typed surface does', async () => {
    // Without `schemas` there is no capability information, so `contains` cannot
    // be narrowed — but the DIALECT is still v3, so `like`/`ilike` must be gone.
    // Otherwise the untyped surface silently hands back the v2 builder type.
    const supabase = await encryptedSupabaseV3(supabaseClient)
    const builder = supabase.from<{ id: number; email: string }>('users')
    builder.contains('email', 'ada')
    // @ts-expect-error — v3 free-text search is token containment: use contains()
    builder.like('email', '%ada%')
    // @ts-expect-error — v3 free-text search is token containment: use contains()
    builder.ilike('email', '%ada%')
  })

  it('keeps like/ilike on the v2 builder', () => {
    const v2Users = v2EncryptedTable('users', {
      email: encryptedColumn('email').freeTextSearch(),
    })
    const v2 = encryptedSupabase({
      encryptionClient: {} as never,
      supabaseClient,
    })
    const builder = v2.from<{ email: string }>('users', v2Users)
    builder.like('email', '%ada%')
    builder.ilike('email', '%ada%')
    // @ts-expect-error — contains is the v3 dialect's method
    builder.contains('email', 'ada')
  })

  it('supports a no-arg select(), like supabase-js', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient)
    supabase.from('users').select()
  })
})
