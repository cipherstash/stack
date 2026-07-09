import { describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'
import { encryptedSupabase } from '@/supabase'
import { EncryptedQueryBuilderV3Impl } from '@/supabase/query-builder-v3'

// ---------------------------------------------------------------------------
// Mocks
//
// The builders only touch a narrow slice of the encryption client and the
// supabase client, so both are simulated: the encryption mock produces
// deterministic fake envelopes (carrying the plaintext in `pt` so the fake
// decrypt can undo them), and the supabase mock records every builder call.
// This pins the WIRE ENCODING each dialect produces — the part of the adapter
// that CI can verify without a live Supabase project.
// ---------------------------------------------------------------------------

type FakeEnvelope = {
  v: 2
  i: { t: string; c: string }
  c: string
  hm: string
  pt: unknown
}

function fakeEnvelope(value: unknown, column: string): FakeEnvelope {
  const pt = value instanceof Date ? value.toISOString() : value
  return {
    v: 2,
    i: { t: 'tbl', c: column },
    c: `ct:${String(pt)}`,
    hm: `hm:${String(pt)}`,
    pt,
  }
}

function isFakeEnvelope(value: unknown): value is FakeEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    'pt' in value &&
    'c' in value &&
    'hm' in value
  )
}

/** A chainable operation resolving to `{ data }`, like the real ones. */
function operation<T>(data: T) {
  const op = {
    withLockContext: () => op,
    audit: () => op,
    then: (
      onfulfilled?: ((value: { data: T }) => unknown) | null,
      onrejected?: ((reason: unknown) => unknown) | null,
    ) => Promise.resolve({ data }).then(onfulfilled, onrejected),
  }
  return op
}

type SchemaLike = {
  build(): { columns: Record<string, unknown> }
  buildColumnKeyMap?(): Record<string, string>
}

function createMockEncryptionClient() {
  const encryptedProps = (table: SchemaLike): string[] =>
    table.buildColumnKeyMap
      ? Object.keys(table.buildColumnKeyMap())
      : Object.keys(table.build().columns)

  const client = {
    encrypt: (value: unknown, opts: { column: { getName(): string } }) =>
      operation(fakeEnvelope(value, opts.column.getName())),

    // v2 filter path: batch query terms as composite literals
    encryptQuery: (terms: Array<{ value: unknown }>) =>
      operation(terms.map((t) => `("${String(t.value)}")`)),

    encryptModel: (model: Record<string, unknown>, table: SchemaLike) => {
      const props = encryptedProps(table)
      const out: Record<string, unknown> = { ...model }
      for (const prop of props) {
        if (out[prop] != null) out[prop] = fakeEnvelope(out[prop], prop)
      }
      return operation(out)
    },

    bulkEncryptModels: (
      models: Record<string, unknown>[],
      table: SchemaLike,
    ) => {
      const props = encryptedProps(table)
      return operation(
        models.map((model) => {
          const out: Record<string, unknown> = { ...model }
          for (const prop of props) {
            if (out[prop] != null) out[prop] = fakeEnvelope(out[prop], prop)
          }
          return out
        }),
      )
    },

    decryptModel: (model: Record<string, unknown>) => {
      const out: Record<string, unknown> = {}
      for (const [key, value] of Object.entries(model)) {
        out[key] = isFakeEnvelope(value) ? value.pt : value
      }
      return operation(out)
    },

    bulkDecryptModels: (models: Record<string, unknown>[]) =>
      operation(
        models.map((model) => {
          const out: Record<string, unknown> = {}
          for (const [key, value] of Object.entries(model)) {
            out[key] = isFakeEnvelope(value) ? value.pt : value
          }
          return out
        }),
      ),
  }

  return client as unknown as EncryptionClient
}

type RecordedCall = { method: string; args: unknown[] }

function createMockSupabase(resultData: unknown = []) {
  const calls: RecordedCall[] = []
  // biome-ignore lint/suspicious/noExplicitAny: test double for the supabase query builder
  const qb: any = {}
  const methods = [
    'select',
    'insert',
    'update',
    'upsert',
    'delete',
    'eq',
    'neq',
    'gt',
    'gte',
    'lt',
    'lte',
    'like',
    'ilike',
    'is',
    'in',
    'filter',
    'not',
    'or',
    'match',
    'order',
    'limit',
    'range',
    'single',
    'maybeSingle',
    'csv',
    'abortSignal',
    'throwOnError',
  ]
  for (const method of methods) {
    qb[method] = (...args: unknown[]) => {
      calls.push({ method, args })
      return qb
    }
  }
  qb.then = (
    onfulfilled?: ((value: unknown) => unknown) | null,
    onrejected?: ((reason: unknown) => unknown) | null,
  ) =>
    Promise.resolve({
      data: resultData,
      error: null,
      count: null,
      status: 200,
      statusText: 'OK',
    }).then(onfulfilled, onrejected)

  const client = { from: (_table: string) => qb }
  const callsFor = (method: string) => calls.filter((c) => c.method === method)

  return { client, calls, callsFor }
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  nickname: types.TextEq('nickname'),
  amount: types.IntegerOrd('amount'),
  createdAt: types.TimestampOrd('created_at'),
  active: types.Boolean('active'),
})

const usersV2 = encryptedTableV2('users', {
  email: encryptedColumn('email').freeTextSearch().equality(),
  age: encryptedColumn('age').dataType('number').equality().orderAndRange(),
})

// DB column names as introspection would report them (id/note are plaintext).
const USERS_ALL_COLUMNS = [
  'id',
  'email',
  'nickname',
  'amount',
  'created_at',
  'active',
  'note',
]

// `encryptedSupabaseV3` is now an async, DB-introspecting factory, so the wire
// tests construct the v3 builder directly. The declared `users` table is kept
// (not a synthesized one) because the `createdAt:created_at::jsonb` assertions
// are inherently about a property→DB rename that a synthesized table — where
// property == DB name — cannot express. `supabase-schema-builder.test.ts`
// proves synthesized ≡ declared byte-for-byte.
function v3Instance(resultData: unknown = []) {
  const supabase = createMockSupabase(resultData)
  const encryptionClient = createMockEncryptionClient()
  const es = {
    from(tableName: string, table: typeof users) {
      return new EncryptedQueryBuilderV3Impl(
        tableName,
        table,
        encryptionClient,
        supabase.client,
        USERS_ALL_COLUMNS,
      )
    },
  }
  return { es, supabase }
}

// ---------------------------------------------------------------------------
// v3 dialect
// ---------------------------------------------------------------------------

describe('encryptedSupabaseV3 wire encoding', () => {
  it('inserts the raw encrypted payload keyed by DB column name (no composite wrap)', async () => {
    const { es, supabase } = v3Instance()

    const createdAt = new Date('2026-01-02T03:04:05.000Z')
    await es
      .from('users', users)
      .insert({ email: 'a@b.com', createdAt, note: 'plain' })

    const [insert] = supabase.callsFor('insert')
    expect(insert).toBeDefined()
    const body = insert.args[0] as Record<string, unknown>

    // Property createdAt lands in DB column created_at
    expect(Object.keys(body).sort()).toEqual(['created_at', 'email', 'note'])
    // Raw envelope — NOT v2's `{ data: ... }` composite wrap
    expect(isFakeEnvelope(body.email)).toBe(true)
    expect((body.email as Record<string, unknown>).data).toBeUndefined()
    expect(isFakeEnvelope(body.created_at)).toBe(true)
    expect(body.note).toBe('plain')
  })

  it('bulk-inserts raw encrypted payloads keyed by DB column name', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .insert([{ email: 'a@b.com' }, { email: 'b@c.com' }])

    const [insert] = supabase.callsFor('insert')
    const body = insert.args[0] as Record<string, unknown>[]
    expect(body).toHaveLength(2)
    expect(isFakeEnvelope(body[0].email)).toBe(true)
    expect(isFakeEnvelope(body[1].email)).toBe(true)
  })

  it('adds ::jsonb casts and aliases property names to DB names in select', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id, email, createdAt')

    const [select] = supabase.callsFor('select')
    expect(select.args[0]).toBe('id, email::jsonb, createdAt:created_at::jsonb')
  })

  it('encrypts equality operands as full-envelope jsonb text', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id, email').eq('email', 'a@b.com')

    const eqCalls = supabase.callsFor('eq')
    expect(eqCalls).toHaveLength(1)
    const [column, term] = eqCalls[0].args
    expect(column).toBe('email')
    // The operand must be the FULL storage envelope (v/i/c + index terms) so
    // it satisfies the public.* domain CHECK when Postgres coerces it.
    const parsed = JSON.parse(term as string)
    expect(parsed.c).toBeDefined()
    expect(parsed.i).toBeDefined()
    expect(parsed.hm).toBeDefined()
  })

  it('passes non-encrypted filters through untouched', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id, email').eq('id', 42)

    const eqCalls = supabase.callsFor('eq')
    expect(eqCalls[0].args).toEqual(['id', 42])
  })

  it('maps property names to DB names in range filters', async () => {
    const { es, supabase } = v3Instance()

    const from = new Date('2026-01-01T00:00:00.000Z')
    await es.from('users', users).select('id, createdAt').gte('createdAt', from)

    const [gte] = supabase.callsFor('gte')
    expect(gte.args[0]).toBe('created_at')
    expect(JSON.parse(gte.args[1] as string).c).toBeDefined()
  })

  it('emits encrypted like/ilike as PostgREST cs (bloom-filter containment)', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id, email').like('email', 'a@b')
    await es.from('users', users).select('id, email').ilike('email', 'a@b')

    const filterCalls = supabase.callsFor('filter')
    expect(filterCalls).toHaveLength(2)
    for (const call of filterCalls) {
      expect(call.args[0]).toBe('email')
      expect(call.args[1]).toBe('cs')
      expect(JSON.parse(call.args[2] as string).c).toBeDefined()
    }
    // No bare like/ilike reached PostgREST for the encrypted column
    expect(supabase.callsFor('like')).toHaveLength(0)
    expect(supabase.callsFor('ilike')).toHaveLength(0)
  })

  it('keeps like on plain columns as like', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id, email').like('note', '%x%')

    expect(supabase.callsFor('like')).toHaveLength(1)
    expect(supabase.callsFor('filter')).toHaveLength(0)
  })

  it('maps not(like) on encrypted columns to not(cs)', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .select('id, email')
      .not('email', 'like', 'a@b')

    const [not] = supabase.callsFor('not')
    expect(not.args[0]).toBe('email')
    expect(not.args[1]).toBe('cs')
  })

  it('encrypts each element of an in() filter', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .select('id, nickname')
      .in('nickname', ['ada', 'grace'])

    const [inCall] = supabase.callsFor('in')
    expect(inCall.args[0]).toBe('nickname')
    const values = inCall.args[1] as string[]
    expect(values).toHaveLength(2)
    expect(JSON.parse(values[0]).pt).toBe('ada')
    expect(JSON.parse(values[1]).pt).toBe('grace')
  })

  it('maps match() keys to DB names and encrypts values', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .select('id, nickname')
      .match({ nickname: 'ada', id: 7 })

    const [match] = supabase.callsFor('match')
    const query = match.args[0] as Record<string, unknown>
    expect(JSON.parse(query.nickname as string).pt).toBe('ada')
    expect(query.id).toBe(7)
  })

  it('rejects a query type the column does not support', async () => {
    const { es } = v3Instance()

    // nickname is public.text_eq — equality only, no order/range
    const { error, status } = await es
      .from('users', users)
      .select('id, nickname')
      .gte('nickname', 'a')

    expect(status).toBe(500)
    expect(error?.message).toContain('does not support orderAndRange')
  })

  it('rejects filters on storage-only columns', async () => {
    const { es } = v3Instance()

    // active is public.boolean — storage only
    const { error, status } = await es
      .from('users', users)
      .select('id')
      // biome-ignore lint/suspicious/noExplicitAny: intentionally bypassing the type guard to prove the runtime guard
      .eq('active' as any, true as any)

    expect(status).toBe(500)
    expect(error?.message).toContain('does not support equality')
  })

  it('maps property names to DB names in order()', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id, createdAt').order('createdAt')

    const [order] = supabase.callsFor('order')
    expect(order.args[0]).toBe('created_at')
  })

  it('leaves plaintext columns untouched in order()', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id, note').order('note')

    const [order] = supabase.callsFor('order')
    expect(order.args[0]).toBe('note')
  })

  it('rejects order() on a column with no orderAndRange capability', async () => {
    const { es } = v3Instance()

    // active is public.boolean — storage only, so ordering it would sort ciphertext
    const { error, status } = await es
      .from('users', users)
      .select('id')
      .order('active')

    expect(status).toBe(500)
    expect(error?.message).toContain('does not support ordering')
  })

  it('maps property names to DB names in the onConflict option', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .upsert({ email: 'a@b.com' }, { onConflict: 'createdAt' })

    const [upsert] = supabase.callsFor('upsert')
    expect((upsert.args[1] as { onConflict: string }).onConflict).toBe(
      'created_at',
    )
  })

  it('maps every column of a multi-column onConflict list', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .upsert({ email: 'a@b.com' }, { onConflict: 'createdAt,amount' })

    const [upsert] = supabase.callsFor('upsert')
    expect((upsert.args[1] as { onConflict: string }).onConflict).toBe(
      'created_at,amount',
    )
  })

  // `or()` had no v3 coverage at all. Any condition naming an encrypted column
  // — under either its property or DB name — routes through
  // `transformOrConditions`, which maps names; the verbatim branch is reached
  // only when every condition names a plaintext column, which needs no mapping.
  it('maps property names to DB names in an or() string', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id').or('createdAt.gte.2026-01-01')

    const [or] = supabase.callsFor('or')
    expect(or.args[0] as string).toMatch(/^created_at\.gte\./)
  })

  it('passes an all-plaintext or() string through verbatim', async () => {
    const { es, supabase } = v3Instance()

    await es.from('users', users).select('id').or('note.eq.x,id.eq.1')

    const [or] = supabase.callsFor('or')
    expect(or.args[0]).toBe('note.eq.x,id.eq.1')
  })

  it('rebuilds a mixed encrypted/plaintext or() string, mapping only the encrypted column', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .select('id')
      .or('createdAt.gte.2026-01-01,note.eq.x')

    // The encrypted operand is a JSON envelope containing commas, so the
    // conditions cannot be split on ','. Assert on the boundaries instead.
    const [or] = supabase.callsFor('or')
    const emitted = or.args[0] as string
    expect(emitted).toMatch(/^created_at\.gte\./)
    expect(emitted.endsWith(',note.eq.x')).toBe(true)
  })

  it('keeps every filter array correlated in a combined query', async () => {
    const { es, supabase } = v3Instance()

    await es
      .from('users', users)
      .select('id, email, createdAt')
      .eq('email', 'a@b.com')
      .not('nickname', 'eq', 'ada')
      .or('createdAt.gte.2026-01-01,note.eq.x')
      .match({ nickname: 'grace' })
      .order('createdAt')
      .limit(5)

    expect(supabase.callsFor('eq')[0].args[0]).toBe('email')
    expect(supabase.callsFor('not')[0].args[0]).toBe('nickname')
    expect(supabase.callsFor('or')[0].args[0] as string).toMatch(
      /^created_at\./,
    )
    expect(
      (supabase.callsFor('match')[0].args[0] as Record<string, unknown>)
        .nickname,
    ).toBeDefined()
    expect(supabase.callsFor('order')[0].args[0]).toBe('created_at')
    expect(supabase.callsFor('limit')[0].args[0]).toBe(5)
  })

  // Filter-capability errors are raised in `encryptFilterValues` (execute step
  // 3); order-capability errors in `validateTransforms`, inside
  // `buildAndExecuteQuery` (step 4). The filter must therefore win. Pins that
  // precedence against a refactor that moves validation earlier.
  it('reports the filter-capability error ahead of the order-capability error', async () => {
    const { es } = v3Instance()

    const { error, status } = await es
      .from('users', users)
      .select('id')
      .gte('nickname', 'a') // text_eq: no orderAndRange
      .order('active') // boolean: storage only

    expect(status).toBe(500)
    expect(error?.message).toContain('does not support orderAndRange')
    expect(error?.message).not.toContain('does not support ordering')
  })

  // `is` is a SQL predicate (PostgREST accepts only null/true/false), never a
  // data operand — and a null operand is SQL NULL, not a value to search for.
  // Only the regular `.is()` filter skipped encryption; every other collector
  // encrypted whatever it was handed. See the v2 block for the released-side
  // regressions.
  describe('is / null operands are never encrypted', () => {
    it('does not encrypt a regular is() operand', async () => {
      const { es, supabase } = v3Instance()
      await es.from('users', users).select('id').is('createdAt', null)
      expect(supabase.callsFor('is')[0].args).toEqual(['created_at', null])
    })

    it('does not encrypt not(col, is, null)', async () => {
      const { es, supabase } = v3Instance()
      await es.from('users', users).select('id').not('createdAt', 'is', null)
      expect(supabase.callsFor('not')[0].args).toEqual([
        'created_at',
        'is',
        null,
      ])
    })

    it('does not encrypt a raw filter() is operand', async () => {
      const { es, supabase } = v3Instance()
      await es.from('users', users).select('id').filter('createdAt', 'is', null)
      expect(supabase.callsFor('filter')[0].args).toEqual([
        'created_at',
        'is',
        null,
      ])
    })

    it('does not encrypt a null match() value', async () => {
      const { es, supabase } = v3Instance()
      await es.from('users', users).select('id').match({ nickname: null })
      expect(supabase.callsFor('match')[0].args[0]).toEqual({ nickname: null })
    })

    // The or-string verbatim branch keys on "was any VALUE encrypted". An `is`
    // on an encrypted column encrypts nothing, so it would fall through to
    // verbatim and forward the unmapped property name. It must rebuild whenever
    // a condition REFERENCES an encrypted column.
    it('maps the column name in an or() string whose only condition is an is', async () => {
      const { es, supabase } = v3Instance()
      await es.from('users', users).select('id').or('createdAt.is.null')
      expect(supabase.callsFor('or')[0].args[0]).toBe('created_at.is.null')
    })

    it('maps names in a structured or() carrying an is', async () => {
      const { es, supabase } = v3Instance()
      await es
        .from('users', users)
        .select('id')
        .or([{ column: 'createdAt', op: 'is', value: null }])
      expect(supabase.callsFor('or')[0].args[0]).toBe('created_at.is.null')
    })

    // `is` maps to the `equality` query type, so before the fix an `is` term
    // reached the v3 capability gate and threw on a storage-only column.
    it('does not raise a capability error for an is on a storage-only column', async () => {
      const { es, supabase } = v3Instance()
      const { status, error } = await es
        .from('users', users)
        .select('id')
        .or('active.is.null')

      expect(error).toBeNull()
      expect(status).toBe(200)
      expect(supabase.callsFor('or')[0].args[0]).toBe('active.is.null')
    })

    it('encrypts the encrypted condition of a mixed or() but leaves the is alone', async () => {
      const { es, supabase } = v3Instance()
      await es
        .from('users', users)
        .select('id')
        .or('nickname.eq.ada,createdAt.is.null')

      const emitted = supabase.callsFor('or')[0].args[0] as string
      expect(emitted).toMatch(/^nickname\.eq\./)
      expect(emitted.endsWith(',created_at.is.null')).toBe(true)
    })
  })

  it('reconstructs Date values from cast_as on decrypted rows', async () => {
    const rows = [
      {
        id: 1,
        email: fakeEnvelope('a@b.com', 'email'),
        createdAt: fakeEnvelope(
          new Date('2026-01-02T03:04:05.000Z'),
          'created_at',
        ),
      },
    ]
    const { es } = v3Instance(rows)

    const { data, error } = await es
      .from('users', users)
      .select('id, email, createdAt')

    expect(error).toBeNull()
    expect(data).toHaveLength(1)
    expect(data![0].email).toBe('a@b.com')
    expect(data![0].createdAt).toBeInstanceOf(Date)
    expect((data![0].createdAt as Date).toISOString()).toBe(
      '2026-01-02T03:04:05.000Z',
    )
  })
})

// ---------------------------------------------------------------------------
// v2 regression — the dialect seams must leave the v2 wire encoding untouched
// ---------------------------------------------------------------------------

describe('encryptedSupabase (v2) wire encoding is unchanged by the dialect seams', () => {
  function v2Instance(resultData: unknown = []) {
    const supabase = createMockSupabase(resultData)
    const es = encryptedSupabase({
      encryptionClient: createMockEncryptionClient(),
      supabaseClient: supabase.client,
    })
    return { es, supabase }
  }

  it('wraps encrypted mutation values in the { data } composite shape', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).insert({ email: 'a@b.com', note: 'x' })

    const [insert] = supabase.callsFor('insert')
    const body = insert.args[0] as Record<string, unknown>
    expect(body.email).toHaveProperty('data')
    expect(isFakeEnvelope((body.email as Record<string, unknown>).data)).toBe(
      true,
    )
    expect(body.note).toBe('x')
  })

  it('encodes filter terms as composite literals via encryptQuery', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id, email').eq('email', 'a@b.com')

    const [eq] = supabase.callsFor('eq')
    expect(eq.args).toEqual(['email', '("a@b.com")'])
  })

  it('keeps like on encrypted columns as like', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id, email').like('email', 'a@b')

    expect(supabase.callsFor('like')).toHaveLength(1)
    expect(supabase.callsFor('filter')).toHaveLength(0)
  })

  it('adds plain ::jsonb casts without aliasing', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id, email, age')

    const [select] = supabase.callsFor('select')
    expect(select.args[0]).toBe('id, email::jsonb, age::jsonb')
  })

  it('passes order() column names through unchanged', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id, age').order('age')

    const [order] = supabase.callsFor('order')
    expect(order.args[0]).toBe('age')
  })

  it('passes the onConflict option through by reference', async () => {
    const { es, supabase } = v2Instance()

    const options = { onConflict: 'email' }
    await es.from('users', usersV2).upsert({ email: 'a@b.com' }, options)

    const [upsert] = supabase.callsFor('upsert')
    expect(upsert.args[1]).toBe(options)
  })

  it('passes an all-plaintext or() string through verbatim', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id').or('id.eq.1,note.eq.x')

    const [or] = supabase.callsFor('or')
    expect(or.args[0]).toBe('id.eq.1,note.eq.x')
  })

  // -------------------------------------------------------------------------
  // Characterization tests for the paths `toDbSpace()` will rewrite. Each pins
  // the correlation between the term collector (`encryptFilterValues`) and the
  // applier (`applyFilters`), which agree only by array index / column name.
  // -------------------------------------------------------------------------

  it('match() encrypts encrypted keys and passes plaintext through', async () => {
    const { es, supabase } = v2Instance()

    await es
      .from('users', usersV2)
      .select('id')
      .match({ email: 'a@b.com', note: 'plain' })

    const [match] = supabase.callsFor('match')
    const query = match.args[0] as Record<string, unknown>
    expect(query.email).toBe('("a@b.com")')
    expect(query.note).toBe('plain')
    // Key order survives the Record -> entries -> Record round-trip
    expect(Object.keys(query)).toEqual(['email', 'note'])
  })

  it('not() encrypts on encrypted columns and passes plaintext through', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id').not('email', 'eq', 'a@b.com')
    await es.from('users', usersV2).select('id').not('note', 'eq', 'plain')

    const [encrypted, plain] = supabase.callsFor('not')
    expect(encrypted.args).toEqual(['email', 'eq', '("a@b.com")'])
    expect(plain.args).toEqual(['note', 'eq', 'plain'])
  })

  it('in() encrypts each element and leaves plaintext arrays alone', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id').in('email', ['a@b.com', 'c@d'])
    await es.from('users', usersV2).select('id').in('note', ['x', 'y'])

    const [encrypted, plain] = supabase.callsFor('in')
    expect(encrypted.args[1]).toEqual(['("a@b.com")', '("c@d")'])
    expect(plain.args[1]).toEqual(['x', 'y'])
  })

  it('is() leaves the value untouched on an encrypted column', async () => {
    const { es, supabase } = v2Instance()

    await es.from('users', usersV2).select('id').is('email', null)

    const [is] = supabase.callsFor('is')
    expect(is.args).toEqual(['email', null])
  })

  it('filter() encrypts the operand on an encrypted column', async () => {
    const { es, supabase } = v2Instance()

    await es
      .from('users', usersV2)
      .select('id')
      .filter('email', 'eq', 'a@b.com')
    await es.from('users', usersV2).select('id').filter('note', 'eq', 'plain')

    const [encrypted, plain] = supabase.callsFor('filter')
    expect(encrypted.args).toEqual(['email', 'eq', '("a@b.com")'])
    expect(plain.args).toEqual(['note', 'eq', 'plain'])
  })

  // The single most important characterization test: a strict nonempty SUBSET
  // of the or-string's conditions is encrypted, so the condition index `j` must
  // agree between the two `parseOrString` calls that `toDbSpace()` collapses
  // into one.
  it('or() rebuilds a mixed encrypted/plaintext string, keeping each condition on its own column', async () => {
    const { es, supabase } = v2Instance()

    await es
      .from('users', usersV2)
      .select('id')
      .or('email.eq.a@b.com,note.eq.x')

    const [or] = supabase.callsFor('or')
    const emitted = or.args[0] as string
    const [emailCond, noteCond] = emitted.split(',')
    expect(emailCond).toContain('email.eq.')
    expect(emailCond).toContain('a@b.com')
    expect(noteCond).toBe('note.eq.x')
  })

  it('keeps every filter array correlated in a combined query', async () => {
    const { es, supabase } = v2Instance()

    await es
      .from('users', usersV2)
      .select('id, email, age')
      .eq('email', 'a@b.com')
      .not('age', 'eq', 30)
      .or('email.eq.c@d,note.eq.x')
      .match({ email: 'e@f.com' })
      .filter('age', 'gte', 18)
      .order('age')
      .limit(10)

    expect(supabase.callsFor('eq')[0].args).toEqual(['email', '("a@b.com")'])
    expect(supabase.callsFor('not')[0].args).toEqual(['age', 'eq', '("30")'])
    expect(supabase.callsFor('or')[0].args[0]).toContain('note.eq.x')
    expect(
      (supabase.callsFor('match')[0].args[0] as Record<string, unknown>).email,
    ).toBe('("e@f.com")')
    expect(supabase.callsFor('filter')[0].args).toEqual([
      'age',
      'gte',
      '("18")',
    ])
    expect(supabase.callsFor('order')[0].args[0]).toBe('age')
    expect(supabase.callsFor('limit')[0].args[0]).toBe(10)
  })

  // Released-side regressions. `is` is a SQL predicate — PostgREST accepts only
  // null/true/false — and a null operand is SQL NULL, never a value to search
  // for. Only the regular `.is()` filter skipped encryption; every other
  // collector encrypted whatever it was handed, emitting operands PostgREST
  // rejects.
  describe('is / null operands are never encrypted', () => {
    it('does not encrypt not(col, is, null)', async () => {
      const { es, supabase } = v2Instance()
      await es.from('users', usersV2).select('id').not('age', 'is', null)
      expect(supabase.callsFor('not')[0].args).toEqual(['age', 'is', null])
    })

    it('does not encrypt a raw filter() is operand', async () => {
      const { es, supabase } = v2Instance()
      await es.from('users', usersV2).select('id').filter('age', 'is', null)
      expect(supabase.callsFor('filter')[0].args).toEqual(['age', 'is', null])
    })

    it('forwards an or() is condition unencrypted', async () => {
      const { es, supabase } = v2Instance()
      await es.from('users', usersV2).select('id').or('age.is.null')
      expect(supabase.callsFor('or')[0].args[0]).toBe('age.is.null')
    })

    it('does not encrypt a null eq() operand', async () => {
      const { es, supabase } = v2Instance()
      await es.from('users', usersV2).select('id').eq('email', null)
      expect(supabase.callsFor('eq')[0].args).toEqual(['email', null])
    })

    it('does not encrypt a null match() value', async () => {
      const { es, supabase } = v2Instance()
      await es.from('users', usersV2).select('id').match({ email: null })
      expect(supabase.callsFor('match')[0].args[0]).toEqual({ email: null })
    })

    it('does not encrypt null elements of an in() list', async () => {
      const { es, supabase } = v2Instance()
      await es
        .from('users', usersV2)
        .select('id')
        .in('email', ['a@b.com', null])
      expect(supabase.callsFor('in')[0].args[1]).toEqual(['("a@b.com")', null])
    })

    it('treats is() as a predicate even with a non-null operand', async () => {
      const { es, supabase } = v2Instance()
      await es.from('users', usersV2).select('id').is('email', false)
      expect(supabase.callsFor('is')[0].args).toEqual(['email', false])
    })
  })
})
