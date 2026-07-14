import {
  encryptedTable,
  type InferPlaintext,
  types,
} from '@cipherstash/stack/eql/v3'
import {
  encryptedColumn,
  encryptedTable as v2EncryptedTable,
} from '@cipherstash/stack/schema'
import { describe, expectTypeOf, it } from 'vitest'
import {
  type EncryptedQueryBuilderV3,
  type EncryptedSupabaseResponse,
  encryptedSupabase,
  encryptedSupabaseV3,
  type SupabaseClientLike,
} from '../src/index.js'

declare const supabaseClient: SupabaseClientLike

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  amount: types.IntegerOrd('amount'),
  createdAt: types.TimestampOrd('created_at'),
  active: types.Boolean('active'),
  nickname: types.TextEq('nickname'),
  bio: types.TextMatch('bio'),
  score: types.IntegerOrdOre('score'),
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
    // @ts-expect-error — score is public.eql_v3_integer_ord_ore: ORE-backed, so
    // orderAndRange-capable but NOT sortable through a jsonb path (its `ob` term
    // needs the superuser-only ORE opclass). Excluded at compile time to match
    // the runtime rejection.
    builder.order('score')
  })

  it('still allows order() on a plaintext row key', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    // `note` is not a declared column, so it is a plaintext passthrough.
    const builder = supabase.from<{ note: string }>('users')
    builder.order('note')
  })

  it('narrows matches() to freeTextSearch-capable columns', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // public.eql_v3_text_search — equality + orderAndRange + freeTextSearch
    builder.matches('email', 'ada')
    // public.eql_v3_text_match — freeTextSearch only
    builder.matches('bio', 'ada')
    // @ts-expect-error — nickname is public.eql_v3_text_eq: no match index
    builder.matches('nickname', 'ada')
    // @ts-expect-error — amount is public.eql_v3_integer_ord: no match index
    builder.matches('amount', 'ada')
    // @ts-expect-error — active is public.eql_v3_boolean (storage only)
    builder.matches('active', 'ada')
  })

  // `matches()` is encrypted free-text ONLY: its operand is the string to
  // tokenize, and a plaintext key is a compile error (use `contains()`).
  it('pins the matches() operand to a string on encrypted columns', () => {
    mixedBuilder.matches('email', 'ada')
    mixedBuilder.matches('bio', 'ada')
    // @ts-expect-error — email is public.eql_v3_text_search: the match term is a string
    mixedBuilder.matches('email', ['ada'])
    // @ts-expect-error — bio is public.eql_v3_text_match: the match term is a string
    mixedBuilder.matches('bio', { a: 1 })
  })

  it('rejects matches() on plaintext keys — use contains()', () => {
    // @ts-expect-error — tags is plaintext; matches() is encrypted free-text only
    mixedBuilder.matches('tags', 'vip')
    // @ts-expect-error — meta is plaintext; matches() is encrypted free-text only
    mixedBuilder.matches('meta', 'vip')
    // @ts-expect-error — a union with a plaintext member is not free-text-only
    mixedBuilder.matches(plaintextKey, 'vip')
    // @ts-expect-error — a mixed union (encrypted + plaintext) is not free-text-only
    mixedBuilder.matches(mixedKey, 'ada')
  })

  // `contains()` is native (exact) containment on PLAINTEXT columns; the operand
  // follows the column shape (`@>` is array/jsonb only). An encrypted key is a
  // compile error (use `matches()`).
  it('accepts native containment operand shapes via contains()', () => {
    mixedBuilder.contains('tags', ['vip'])
    mixedBuilder.contains('tags', 'vip')
    mixedBuilder.contains('meta', { plan: 'pro' })
    mixedBuilder.contains(plaintextKey, ['vip'])
    mixedBuilder.contains(plaintextKey, { plan: 'pro' })
  })

  it('rejects contains() on encrypted keys — use matches()', () => {
    // @ts-expect-error — email is encrypted; contains() is native (plaintext) only
    mixedBuilder.contains('email', 'ada')
    // @ts-expect-error — bio is encrypted; contains() is native (plaintext) only
    mixedBuilder.contains('bio', 'ada')
    // @ts-expect-error — a mixed union includes the encrypted email
    mixedBuilder.contains(mixedKey, ['vip'])
  })

  // `@>` is defined on arrays and jsonb, not on a scalar, so the operand type
  // must follow the column's own shape rather than admitting every native
  // containment value on every plaintext key.
  it('rejects a container operand on a plaintext scalar column', () => {
    // @ts-expect-error — note is plaintext text: `text @> text[]` does not exist
    mixedBuilder.contains('note', ['vip'])
    // @ts-expect-error — note is plaintext text: `text @> jsonb` does not exist
    mixedBuilder.contains('note', { a: 1 })
    // @ts-expect-error — a scalar column supports no container operand at all
    mixedBuilder.contains('note', 'vip')
  })

  it('does not expose like/ilike on the v3 builder, at any chain depth', async () => {
    const supabase = await encryptedSupabaseV3(supabaseClient, {
      schemas: { users },
    })
    const builder = supabase.from('users')
    // @ts-expect-error — v3 free-text search is token containment: use matches()
    builder.like('email', '%ada%')
    // @ts-expect-error — v3 free-text search is token containment: use matches()
    builder.ilike('email', '%ada%')
    // The chain must not launder the removal back in via a widened return type.
    // @ts-expect-error — use matches()
    builder.select('id').eq('email', 'a@b.com').like('email', '%ada%')
    // matches() survives the chain.
    builder.select('id').eq('email', 'a@b.com').matches('email', 'ada')
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

  it('exposes matches and contains, but not like/ilike', async () => {
    // Without `schemas` there is no capability information, so neither `matches`
    // nor `contains` can be narrowed — but the DIALECT is still v3, so
    // `like`/`ilike` must be gone. Otherwise the untyped surface silently hands
    // back the v2 builder type. The untyped v3 builder exposes BOTH the encrypted
    // free-text `matches` and the native `contains`.
    const supabase = await encryptedSupabaseV3(supabaseClient)
    const builder = supabase.from<{ id: number; email: string }>('users')
    builder.matches('email', 'ada')
    builder.contains('email', 'ada')
    // @ts-expect-error — v3 free-text search is token containment: use matches()
    builder.like('email', '%ada%')
    // @ts-expect-error — v3 free-text search is token containment: use matches()
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
