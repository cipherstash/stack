import { describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'
import { encryptedSupabase, encryptedSupabaseV3 } from '@/supabase'

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
  amount: types.Int4Ord('amount'),
  createdAt: types.TimestamptzOrd('created_at'),
  active: types.Bool('active'),
})

const usersV2 = encryptedTableV2('users', {
  email: encryptedColumn('email').freeTextSearch().equality(),
  age: encryptedColumn('age').dataType('number').equality().orderAndRange(),
})

// Explicit row type: the default `Row` is exactly the table's plaintext shape,
// so passthrough columns (id, note) need an explicit `Row` to be filterable /
// insertable at the type level.
type UserRow = {
  id: number
  email: string
  nickname: string
  amount: number
  createdAt: Date
  active: boolean
  note: string
}

function v3Instance(resultData: unknown = []) {
  const supabase = createMockSupabase(resultData)
  const es = encryptedSupabaseV3({
    encryptionClient: createMockEncryptionClient(),
    supabaseClient: supabase.client,
  })
  const from = () => es.from<typeof users, UserRow>('users', users)
  return { es, from, supabase }
}

// ---------------------------------------------------------------------------
// v3 dialect
// ---------------------------------------------------------------------------

describe('encryptedSupabaseV3 wire encoding', () => {
  it('inserts the raw encrypted payload keyed by DB column name (no composite wrap)', async () => {
    const { from, supabase } = v3Instance()

    const createdAt = new Date('2026-01-02T03:04:05.000Z')
    await from().insert({ email: 'a@b.com', createdAt, note: 'plain' })

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
    const { from, supabase } = v3Instance()

    await from().insert([{ email: 'a@b.com' }, { email: 'b@c.com' }])

    const [insert] = supabase.callsFor('insert')
    const body = insert.args[0] as Record<string, unknown>[]
    expect(body).toHaveLength(2)
    expect(isFakeEnvelope(body[0].email)).toBe(true)
    expect(isFakeEnvelope(body[1].email)).toBe(true)
  })

  it('adds ::jsonb casts and aliases property names to DB names in select', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, email, createdAt')

    const [select] = supabase.callsFor('select')
    expect(select.args[0]).toBe('id, email::jsonb, createdAt:created_at::jsonb')
  })

  it('encrypts equality operands as full-envelope jsonb text', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, email').eq('email', 'a@b.com')

    const eqCalls = supabase.callsFor('eq')
    expect(eqCalls).toHaveLength(1)
    const [column, term] = eqCalls[0].args
    expect(column).toBe('email')
    // The operand must be the FULL storage envelope (v/i/c + index terms) so
    // it satisfies the eql_v3 domain CHECK when Postgres coerces it.
    const parsed = JSON.parse(term as string)
    expect(parsed.c).toBeDefined()
    expect(parsed.i).toBeDefined()
    expect(parsed.hm).toBeDefined()
  })

  it('passes non-encrypted filters through untouched', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, email').eq('id', 42)

    const eqCalls = supabase.callsFor('eq')
    expect(eqCalls[0].args).toEqual(['id', 42])
  })

  it('maps property names to DB names in range filters', async () => {
    const { from, supabase } = v3Instance()

    const lowerBound = new Date('2026-01-01T00:00:00.000Z')
    await from().select('id, createdAt').gte('createdAt', lowerBound)

    const [gte] = supabase.callsFor('gte')
    expect(gte.args[0]).toBe('created_at')
    expect(JSON.parse(gte.args[1] as string).c).toBeDefined()
  })

  it('emits encrypted like/ilike as PostgREST cs (bloom-filter containment)', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, email').like('email', 'a@b')
    await from().select('id, email').ilike('email', 'a@b')

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
    const { from, supabase } = v3Instance()

    await from().select('id, email').like('note', '%x%')

    expect(supabase.callsFor('like')).toHaveLength(1)
    expect(supabase.callsFor('filter')).toHaveLength(0)
  })

  it('maps not(like) on encrypted columns to not(cs)', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, email').not('email', 'like', 'a@b')

    const [not] = supabase.callsFor('not')
    expect(not.args[0]).toBe('email')
    expect(not.args[1]).toBe('cs')
  })

  it('encrypts each element of an in() filter', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, nickname').in('nickname', ['ada', 'grace'])

    const [inCall] = supabase.callsFor('in')
    expect(inCall.args[0]).toBe('nickname')
    const values = inCall.args[1] as string[]
    expect(values).toHaveLength(2)
    expect(JSON.parse(values[0]).pt).toBe('ada')
    expect(JSON.parse(values[1]).pt).toBe('grace')
  })

  it('maps match() keys to DB names and encrypts values', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, nickname').match({ nickname: 'ada', id: 7 })

    const [match] = supabase.callsFor('match')
    const query = match.args[0] as Record<string, unknown>
    expect(JSON.parse(query.nickname as string).pt).toBe('ada')
    expect(query.id).toBe(7)
  })

  it('rejects a query type the column does not support', async () => {
    const { from } = v3Instance()

    // nickname is eql_v3.text_eq — equality only, no order/range
    const { error, status } = await from()
      .select('id, nickname')
      .gte('nickname', 'a')

    expect(status).toBe(500)
    expect(error?.message).toContain('does not support orderAndRange')
  })

  it('rejects filters on storage-only columns', async () => {
    const { from } = v3Instance()

    // active is eql_v3.bool — storage only
    const { error, status } = await from()
      .select('id')
      // biome-ignore lint/suspicious/noExplicitAny: intentionally bypassing the type guard to prove the runtime guard
      .eq('active' as any, true as any)

    expect(status).toBe(500)
    expect(error?.message).toContain('does not support equality')
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
    const { from } = v3Instance(rows)

    const { data, error } = await from().select('id, email, createdAt')

    expect(error).toBeNull()
    expect(data).toHaveLength(1)
    expect(data![0].email).toBe('a@b.com')
    expect(data![0].createdAt).toBeInstanceOf(Date)
    expect((data![0].createdAt as Date).toISOString()).toBe(
      '2026-01-02T03:04:05.000Z',
    )
  })

  it('reconstructs Date values selected under a user-chosen PostgREST alias', async () => {
    const rows = [
      {
        id: 1,
        ts: fakeEnvelope(new Date('2026-01-02T03:04:05.000Z'), 'created_at'),
      },
    ]
    const { from, supabase } = v3Instance(rows)

    const { data, error } = await from().select('id, ts:createdAt')

    // The alias resolves through the property to the DB column…
    const [select] = supabase.callsFor('select')
    expect(select.args[0]).toBe('id, ts:created_at::jsonb')

    // …and the aliased key still gets cast_as-driven Date reconstruction.
    expect(error).toBeNull()
    const row = data![0] as Record<string, unknown>
    expect(row.ts).toBeInstanceOf(Date)
    expect((row.ts as Date).toISOString()).toBe('2026-01-02T03:04:05.000Z')
  })

  it('rebuilds structured or() conditions with DB names, cs remap, and encrypted operands', async () => {
    const { from, supabase } = v3Instance()

    await from()
      .select('id, email, createdAt')
      .or([
        { column: 'email', op: 'ilike', value: 'a@b' },
        { column: 'createdAt', op: 'gte', value: new Date('2026-01-01') },
        { column: 'id', op: 'eq', value: 7 },
      ])

    const [or] = supabase.callsFor('or')
    const orString = or.args[0] as string

    // Encrypted ilike → cs, property → DB name, operand = quoted envelope
    expect(orString).toContain('email.cs.')
    expect(orString).not.toContain('email.ilike.')
    expect(orString).toContain('created_at.gte.')
    // Plain condition passes through untouched
    expect(orString).toContain('id.eq.7')
    // Encrypted operands are the full envelope (double-quoted by the
    // or-string formatter because JSON contains reserved characters)
    expect(orString).toContain('"{')
  })

  it('rebuilds string-form or() with encrypted conditions remapped', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, email').or('email.eq.a@b.com,id.eq.7')

    const [or] = supabase.callsFor('or')
    const orString = or.args[0] as string
    // The encrypted value is substituted; the plain condition survives as-is
    expect(orString).toContain('email.eq."{')
    expect(orString).toContain('id.eq.7')
  })

  it('passes a string-form or() through verbatim when no condition is encrypted', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id').or('id.eq.7,note.eq.x')

    const [or] = supabase.callsFor('or')
    expect(or.args[0]).toBe('id.eq.7,note.eq.x')
  })

  it('rejects a null operand with a pointer to .is()', async () => {
    const { from } = v3Instance()

    const { error, status } = await from()
      .select('id, email')
      // biome-ignore lint/suspicious/noExplicitAny: intentionally bypassing the type guard to prove the runtime guard
      .eq('email', null as any)

    expect(status).toBe(500)
    expect(error?.message).toContain('null filter value')
    expect(error?.message).toContain(".is('email', null)")
  })

  it('still routes .is() null checks through untouched', async () => {
    const { from, supabase } = v3Instance()

    await from().select('id, email').is('email', null)

    const [isCall] = supabase.callsFor('is')
    expect(isCall.args).toEqual(['email', null])
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
})
