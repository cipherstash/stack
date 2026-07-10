import { describe, expectTypeOf, it } from 'vitest'
import { encryptedTable, type InferPlaintext, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as v2EncryptedTable } from '@/schema'
import {
  type EncryptedQueryBuilderV3,
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

/**
 * A declared table whose ROW also carries plaintext passthrough columns —
 * `tags` (text[]), `meta` (jsonb) and `note` (a SCALAR text column).
 * `InferPlaintext` alone yields only the declared encrypted columns, so this is
 * the shape that exercises the plaintext half of `V3FreeTextSearchableKeys`.
 */
declare const mixedBuilder: EncryptedQueryBuilderV3<
  typeof users,
  UserRow & { tags: string[]; meta: Record<string, unknown>; note: string }
>

/** A column key that is a UNION spanning an encrypted and a plaintext column. */
declare const mixedKey: 'email' | 'tags'
/** A column key that is a union of plaintext columns only. */
declare const plaintextKey: 'tags' | 'meta'

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
    // @ts-expect-error — active is public.eql_v3_boolean (storage only)
    builder.eq('active', true)
    // @ts-expect-error — you cannot IS TRUE-compare a ciphertext to a plaintext
    builder.is('active', true)
  })

  // Every encrypted column stores a jsonb envelope, whether or not it carries a
  // query capability. `IS TRUE` compares that envelope to a plaintext boolean —
  // a database type error, not a filter. Gating the boolean form on the
  // FILTERABLE keys only excluded the storage-only columns, so a queryable
  // encrypted column like `email` slipped through.
  it('rejects is(col, true) on queryable encrypted columns', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // @ts-expect-error — email is public.eql_v3_text_search: a jsonb ciphertext
    builder.is('email', true)
    // @ts-expect-error — nickname is public.eql_v3_text_eq: a jsonb ciphertext
    builder.is('nickname', false)
    // @ts-expect-error — amount is public.eql_v3_integer_ord: a jsonb ciphertext
    builder.is('amount', true)
  })

  // `IS NULL` is forwarded unencrypted (a NULL plaintext is stored as a SQL
  // NULL, not a ciphertext), and it is the ONLY predicate a storage-only column
  // supports — so it must not be gated behind the filterable-key narrowing.
  it('allows is(col, null) on every column, including storage-only ones', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    builder.is('active', null)
    builder.is('email', null)
  })

  it('allows order() on encrypted columns that carry an ordering term', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // The builder does not emit a bare `ORDER BY col` — that would sort the
    // ciphertext envelope through jsonb's default opclass. It emits the jsonb
    // path `col->>op`, which selects the OPE term, and OPE is order-preserving.
    builder.order('createdAt')
    builder.order('amount', { ascending: false })
    // `text_search` carries `ope` alongside its match and equality terms.
    builder.order('email')
  })

  it('rejects order() on encrypted columns with no ordering term', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // @ts-expect-error — active is public.eql_v3_boolean: storage only
    builder.order('active')
    // @ts-expect-error — nickname is public.eql_v3_text_eq: equality only
    builder.order('nickname')
    // @ts-expect-error — bio is public.eql_v3_text_match: match only
    builder.order('bio')
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
    // public.eql_v3_text_search — equality + orderAndRange + freeTextSearch
    builder.contains('email', 'ada')
    // public.eql_v3_text_match — freeTextSearch only
    builder.contains('bio', 'ada')
    // @ts-expect-error — nickname is public.eql_v3_text_eq: no match index
    builder.contains('nickname', 'ada')
    // @ts-expect-error — amount is public.eql_v3_integer_ord: no match index
    builder.contains('amount', 'ada')
    // @ts-expect-error — active is public.eql_v3_boolean (storage only)
    builder.contains('active', 'ada')
  })

  // `V3FreeTextSearchableKeys` deliberately admits plaintext row keys so that
  // `contains()` reaches PostgREST's NATIVE jsonb/array containment — which the
  // runtime already does, forwarding a non-encrypted operand straight to
  // `q.contains`. A blanket `value: string` made that unreachable from
  // TypeScript: the operand type must follow the column.
  it('accepts native containment operands on a plaintext key', () => {
    mixedBuilder.contains('tags', ['vip'])
    mixedBuilder.contains('meta', { plan: 'pro' })
    mixedBuilder.contains('tags', 'vip')
  })

  it('still pins an encrypted text-search operand to string', () => {
    mixedBuilder.contains('email', 'ada')
    // @ts-expect-error — email is public.eql_v3_text_search: the match term is a string
    mixedBuilder.contains('email', ['ada'])
    // @ts-expect-error — bio is public.eql_v3_text_match: the match term is a string
    mixedBuilder.contains('bio', { a: 1 })
  })

  // A union column key is only as permissive as its STRICTEST member. If any
  // member is a declared encrypted column the operand must be the string term:
  // that member's runtime path hands the operand to `encrypt()`, which has no
  // plaintext-type guard, so an array reaches protect-ffi as the plaintext for a
  // `cast_as: text` column.
  it('pins a mixed union key to the encrypted string operand', () => {
    mixedBuilder.contains(mixedKey, 'ada')
    // @ts-expect-error — the union includes email (public.eql_v3_text_search)
    mixedBuilder.contains(mixedKey, ['vip'])
    // @ts-expect-error — the union includes email (public.eql_v3_text_search)
    mixedBuilder.contains(mixedKey, { plan: 'pro' })
  })

  it('leaves a union of plaintext keys on the native operand', () => {
    mixedBuilder.contains(plaintextKey, ['vip'])
    mixedBuilder.contains(plaintextKey, { plan: 'pro' })
  })

  // `@>` is defined on arrays and jsonb, not on a scalar. Postgres answers a
  // containment query against a plaintext `text` column with 42883
  // (operator does not exist), so the operand type must follow the column's own
  // shape rather than admitting every native containment value on every
  // plaintext key.
  it('rejects containment on a plaintext scalar column', () => {
    // @ts-expect-error — note is plaintext text: `text @> text[]` does not exist
    mixedBuilder.contains('note', ['vip'])
    // @ts-expect-error — note is plaintext text: `text @> jsonb` does not exist
    mixedBuilder.contains('note', { a: 1 })
    // @ts-expect-error — a scalar column supports no containment operand at all
    mixedBuilder.contains('note', 'vip')
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

  // No `schemas` means no capability information, so nothing here can tell an
  // encrypted match column from a plaintext jsonb one. The operand must accept
  // both — the runtime decides which by looking the column up.
  it('accepts native containment operands, having no capability info to narrow with', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient)
    const builder = supabase.from<{
      id: number
      tags: string[]
      meta: Record<string, unknown>
    }>('users')
    builder.contains('tags', ['vip'])
    builder.contains('meta', { plan: 'pro' })
    builder.contains('tags', 'vip')
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
