/**
 * The supabase v3 adapter, executed against a real PostgREST and real
 * `public.*` domains, as the `anon` role.
 *
 * Every other supabase v3 test drives `createMockSupabase` — an argument
 * recorder with no SQL behind it. It can prove the adapter EMITS
 * `email.cs."{…}"`; it cannot prove PostgREST parses that, that `cs` maps to
 * `@>` on a domain column, that a full storage envelope clears the domain CHECK
 * as a filter operand, or that `anon` holds the grants those operators need.
 * Those are exactly the things that break in production, and this is the only
 * suite that runs them.
 *
 * ## No CipherStash credentials
 * The domain CHECKs are structural (`v`/`i`/`c` + the domain's index terms),
 * not cryptographic, so `helpers/v3-envelope.ts` builds valid envelopes
 * directly and the encryption client is a stub. The REAL parts are the adapter,
 * `@supabase/postgrest-js`, PostgREST, the domains, the `eql_v3` operators and
 * the Supabase grants. What is faked is ZeroKMS — and only ZeroKMS.
 *
 * Consequently this suite must never assert ORDER semantics: synthetic ORE
 * terms compare equal to themselves and are otherwise meaningless.
 * `drizzle-v3/operators-live-pg.test.ts` proves ordering with real ciphertext.
 *
 * ## As `anon`, not as the owner
 * `PGRST_DB_ANON_ROLE=anon` and PostgREST connects as `authenticator`, a
 * non-superuser member of `anon`. Pointing it at the DB owner would make every
 * permission check pass vacuously. Running as `anon` is what caught
 * `permission denied for schema eql_v3_internal` (see `supabase-v3-grants-pg`).
 */

import type { EncryptionClient } from '@cipherstash/stack/encryption'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { databaseUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EncryptedQueryBuilderV3Impl } from '../src/query-builder-v3'
import { makePostgrestClient, reloadSchemaCache } from './helpers/pgrest'
import { narrowedQueryTerm, storageEnvelope } from './helpers/v3-envelope'

const TABLE = 'protect_ci_v3_pgrest'

const sql = postgres(databaseUrl(), { prepare: false })

// A DECLARED table: `createdAt → created_at` is the rename the aliasing
// `prop:db_name::jsonb` select exists for, and a synthesized table (property ==
// DB name) cannot express it.
const users = encryptedTable(TABLE, {
  email: types.TextSearch('email'),
  nickname: types.TextEq('nickname'),
  amount: types.IntegerOrd('amount'),
  createdAt: types.TimestampOrd('created_at'),
  active: types.Boolean('active'),
})

/** Which index terms each DB column's domain CHECK demands. */
const COLUMN_TERMS: Record<
  string,
  { hmac?: boolean; ope?: boolean; bloom?: boolean }
> = {
  email: { hmac: true, ope: true, bloom: true }, // text_search — hm + op + bf
  nickname: { hmac: true }, // text_eq
  amount: { ope: true }, // integer_ord — op (CLLW-OPE, eql-3.0.0)
  created_at: { ope: true }, // timestamp_ord
  active: {}, // boolean — storage only
}

/**
 * Deterministic stand-in for protect-ffi's match tokenizer: `ngram`
 * (`token_length: 3`) + `downcase`, hashed into the bloom's bit domain.
 *
 * TRIGRAMS ONLY, deliberately. This suite has no CipherStash credentials and
 * mints its own envelopes, so this function IS the bloom oracle for both the
 * seeded rows and the query needles — anything it invents, the tests below will
 * dutifully confirm. It previously prepended the whole value as an extra token
 * to emulate `include_original: true`, which made a substring `contains` fail
 * and pinned that failure as expected behaviour.
 *
 * protect-ffi does no such thing: `include_original` is accepted and ignored
 * (measured across 0.24 and 0.29, EQL v2 and v3 — the emitted bloom is
 * trigram-only under either setting). Substring `contains` works, as
 * `drizzle-v3/operators-live-pg.test.ts` proves against real ffi and real
 * Postgres.
 *
 * A value shorter than `token_length` yields NO tokens, matching real ffi's
 * empty bloom — the fail-open `matchNeedleError` exists to reject.
 */
function bloomTokens(value: string): number[] {
  const hash = (s: string) => {
    let h = 2166136261
    for (let i = 0; i < s.length; i++)
      h = ((h ^ s.charCodeAt(i)) * 16777619) >>> 0
    return h % 2048
  }
  const lower = value.toLowerCase()
  const tokens: number[] = []
  for (let i = 0; i + 3 <= lower.length; i++)
    tokens.push(hash(lower.slice(i, i + 3)))
  return tokens
}

function seedOf(value: unknown): number {
  const s = String(value)
  let h = 7
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0
  return h
}

/** Plaintext is carried in `c` so the stub decrypt can undo it. Nothing in the
 * domain CHECK inspects `c` beyond its presence. */
function envelopeFor(
  value: unknown,
  dbColumn: string,
): Record<string, unknown> {
  const terms = COLUMN_TERMS[dbColumn] ?? {}
  const pt = value instanceof Date ? value.toISOString() : value
  const env = storageEnvelope({
    table: TABLE,
    column: dbColumn,
    seed: seedOf(pt),
    hmac: terms.hmac ? String(pt) : undefined,
    ope: terms.ope,
    bloom: terms.bloom ? bloomTokens(String(pt)) : undefined,
  })
  env.c = `ct:${JSON.stringify(pt)}`
  return env
}

function decryptValue(value: unknown): unknown {
  if (value && typeof value === 'object' && 'c' in value) {
    const c = (value as { c: string }).c
    if (typeof c === 'string' && c.startsWith('ct:'))
      return JSON.parse(c.slice(3))
  }
  return value
}

/** Chainable op, matching the real encryption client's surface. */
function op<T>(data: T) {
  const self = {
    withLockContext: () => self,
    audit: () => self,
    then: (
      onfulfilled?: ((value: { data: T }) => unknown) | null,
      onrejected?: ((reason: unknown) => unknown) | null,
    ) => Promise.resolve({ data }).then(onfulfilled, onrejected),
  }
  return self
}

const PROP_TO_DB = users.buildColumnKeyMap()

function stubEncryptionClient(): EncryptionClient {
  const encryptModel = (model: Record<string, unknown>) => {
    const out: Record<string, unknown> = { ...model }
    for (const [prop, dbName] of Object.entries(PROP_TO_DB)) {
      if (out[prop] != null) out[prop] = envelopeFor(out[prop], dbName)
    }
    return op(out)
  }
  const decryptModel = (model: Record<string, unknown>) => {
    const out: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(model))
      out[key] = decryptValue(value)
    return op(out)
  }
  const client = {
    // The adapter passes the COLUMN BUILDER; its getName() is the DB name.
    encrypt: (value: unknown, opts: { column: { getName(): string } }) =>
      op(envelopeFor(value, opts.column.getName())),
    encryptModel,
    bulkEncryptModels: (models: Record<string, unknown>[]) =>
      op(
        models.map((m) => {
          const out: Record<string, unknown> = { ...m }
          for (const [prop, dbName] of Object.entries(PROP_TO_DB)) {
            if (out[prop] != null) out[prop] = envelopeFor(out[prop], dbName)
          }
          return out
        }),
      ),
    decryptModel,
    bulkDecryptModels: (models: Record<string, unknown>[]) =>
      op(
        models.map((m) => {
          const out: Record<string, unknown> = {}
          for (const [k, v] of Object.entries(m)) out[k] = decryptValue(v)
          return out
        }),
      ),
  }
  return client as unknown as EncryptionClient
}

const ALL_COLUMNS = [
  'id',
  'row_key',
  'email',
  'nickname',
  'amount',
  'created_at',
  'active',
  'note',
  'tags',
  'meta',
]

// biome-ignore lint/suspicious/noExplicitAny: the suite addresses columns outside the declared row type
function from(): any {
  return new EncryptedQueryBuilderV3Impl(
    TABLE,
    users,
    stubEncryptionClient(),
    makePostgrestClient(),
    ALL_COLUMNS,
  )
}

const ADA_CREATED = new Date('2026-01-02T03:04:05.000Z')

beforeAll(async () => {
  // EQL v3 and the Supabase grants are installed once per run by `globalSetup`,
  // which shells out to the real `stash eql install --eql-version 3 --supabase`.
  // Re-applying them here would only test a hand-rolled approximation.
  await sql.unsafe(`DROP TABLE IF EXISTS ${TABLE}`)
  await sql.unsafe(`
    CREATE TABLE ${TABLE} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      email public.eql_v3_text_search,
      nickname public.eql_v3_text_eq,
      amount public.eql_v3_integer_ord,
      created_at public.eql_v3_timestamp_ord,
      active public.eql_v3_boolean,
      note TEXT,
      -- Plaintext passthrough columns. contains() on these is PostgREST's
      -- NATIVE containment (cs, i.e. the @> Postgres declares on array and
      -- jsonb), not the bloom-filter operator the encrypted domains declare.
      -- Only a real server can prove the adapter emits an operand each accepts.
      tags TEXT[],
      meta JSONB
    )
  `)
  // The grants block covers eql_v3 objects, not application tables.
  await sql.unsafe(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ${TABLE} TO anon, authenticated`,
  )

  await reloadSchemaCache(sql, TABLE)
}, 180_000)

afterAll(async () => {
  await sql.unsafe(`DROP TABLE IF EXISTS ${TABLE}`)
  await sql.end()
})

describe('supabase v3 adapter over real PostgREST (wire + grants)', () => {
  it('inserts raw envelopes that clear every domain CHECK, as anon', async () => {
    const { error, status } = await from().insert({
      row_key: 'ada',
      email: 'ada@example.com',
      nickname: 'ada',
      amount: 42,
      createdAt: ADA_CREATED,
      active: true,
      note: 'plain',
      tags: ['vip', 'admin'],
      meta: { plan: 'pro', seats: 3 },
    })

    expect(error).toBeNull()
    expect(status).toBeLessThan(300)
  })

  // The load-bearing claim in `query-builder-v3.ts`: a narrowed `encryptQuery`
  // term carries no `c` and fails the CHECK with 23514 for EVERY domain, which
  // is why filter operands are full storage envelopes. Sent straight to
  // PostgREST — the adapter cannot produce this shape.
  it('rejects a narrowed encryptQuery-shaped term with 23514', async () => {
    const client = makePostgrestClient() as unknown as {
      from(t: string): {
        insert(body: unknown): Promise<{ error: { code?: string } | null }>
      }
    }
    const { error } = await client.from(TABLE).insert({
      row_key: 'narrowed',
      email: narrowedQueryTerm({
        table: TABLE,
        column: 'email',
        seed: 1,
        hmac: 'x',
        ope: true,
        bloom: [1, 2],
      }),
    })

    expect(error?.code).toBe('23514')
  })

  it('aliases the renamed column and reconstructs its Date', async () => {
    const { data, error } = await from()
      .select('row_key, createdAt')
      .eq('row_key', 'ada')

    expect(error).toBeNull()
    expect(data).toHaveLength(1)
    expect(data[0].createdAt).toBeInstanceOf(Date)
    expect((data[0].createdAt as Date).toISOString()).toBe(
      ADA_CREATED.toISOString(),
    )
  })

  it('matches an eq() filter whose operand is a full storage envelope', async () => {
    const { data, error } = await from().select('row_key').eq('nickname', 'ada')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // Executes `>=` through `eql_v3.gte` → `ord_term` → `eql_v3_internal`, which
  // is the call chain the grants fix unblocked. Compares a term against itself,
  // so it must match; no order semantics are asserted (synthetic ORE terms
  // carry none).
  it('executes a gte() range filter through the ORE operators', async () => {
    const { data, error } = await from()
      .select('row_key')
      .gte('createdAt', ADA_CREATED)

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // EQL 3.0.2 moved encrypted matching to `@@` with a typed query-domain RHS.
  // PostgREST cannot express that cast, so the adapter must fail before it
  // encrypts a storage envelope into the request URL.
  it('fails encrypted free-text filters at the PostgREST boundary', () => {
    expect(() => from().select('row_key').matches('email', 'ada')).toThrow(
      /EQL 3\.0\.2\+.*query_\* cast.*PostgREST/s,
    )
    expect(() => from().select('row_key').like('email', '%ada%')).toThrow(
      /EQL 3\.0\.2\+/,
    )
  })

  // PostgREST must re-parse a double-quoted JSON envelope inside `or=(…)`. The
  // envelope's own quotes and backslashes have to be escaped or the logic tree
  // fails to parse with PGRST100.
  it('re-parses a quoted envelope inside an or() condition', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or('nickname.eq.ada,row_key.eq.nobody')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // An `in`-list inside `or()` has never been executed against a real PostgREST.
  // Each element is a separate JSON envelope, so the list is a comma-separated
  // sequence of quote-dense operands nested inside `(…)` inside the or-tree —
  // the densest thing this adapter emits. A mock cannot catch a PGRST100 here.
  it('parses an encrypted in-list inside an or() condition', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or('nickname.in.(ada,nobody)')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // PostgREST negation: `column.not.<op>.<value>`. The parser used to read `not`
  // AS the operator, encrypt the literal string `in.(ada,nobody)` as one
  // plaintext, and emit a filter that silently matched nothing.
  it('parses a NEGATED encrypted in-list inside an or() condition', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or('nickname.not.in.(ada,nobody)')

    expect(error).toBeNull()
    // `ada` is the only row and it IS in the list, so negation excludes it.
    // Before the fix this returned `['ada']`: the bogus operand matched nothing,
    // and `not` of nothing is everything.
    expect(data).toEqual([])
  })

  // ---------------------------------------------------------------------------
  // Plaintext containment. `contains` is the one FilterOp that is a supabase-js
  // METHOD name and not a PostgREST operator, so a structured `or()` used to
  // emit `tags.contains.{…}` — PGRST100. Translating the token alone is not
  // enough: `cs` takes a containment literal, so the `(a,b)` in-list form arrays
  // otherwise get fails with 22P02. Both are executed here, against a real
  // server, because a mock can only prove what string we emit.
  // ---------------------------------------------------------------------------

  it('runs a native array containment through .contains() on a plaintext column', async () => {
    const { data, error } = await from()
      .select('row_key')
      .contains('tags', ['vip'])

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  it('runs a native jsonb containment through .contains() on a plaintext column', async () => {
    const { data, error } = await from()
      .select('row_key')
      .contains('meta', { plan: 'pro' })

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  it('executes a structured or() contains on a plaintext array column', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or([{ column: 'tags', op: 'contains', value: ['vip', 'admin'] }])

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  it('executes a structured or() contains on a plaintext jsonb column', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or([{ column: 'meta', op: 'contains', value: { plan: 'pro' } }])

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // A containment literal's braces hold top-level commas. Naming an encrypted
  // column forces the parse → rebuild path, where those commas must not be read
  // as condition separators — otherwise `tags` is filtered on a truncated
  // `{vip` and the whole or-tree quietly returns the wrong rows.
  it('preserves a plaintext containment literal in a mixed or() string', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or('nickname.eq.nobody,tags.cs.{vip,admin}')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  it('matches nothing when the containment literal is not contained', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or([{ column: 'tags', op: 'contains', value: ['vip', 'absent'] }])

    expect(error).toBeNull()
    expect(data).toEqual([])
  })

  it('parses a negated encrypted scalar inside an or() condition', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or('nickname.not.eq.nobody')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // `is` reaches Postgres as `is` with a bare `null` — never encrypted. This is
  // the wire shape `fd33aadf` established and it had never been executed.
  it('sends is.null on an encrypted column unencrypted', async () => {
    const { data, error } = await from()
      .select('row_key')
      .or('createdAt.is.null')

    expect(error).toBeNull()
    expect(data).toEqual([])
  })

  // The `in()` method path, executed for the first time against a real server.
  // Each element is its own quote-dense envelope, so the operand is the densest
  // list PostgREST has to parse outside an or-tree.
  it('matches an encrypted in-list through the in() method', async () => {
    const { data, error } = await from()
      .select('row_key')
      .in('nickname', ['ada', 'nobody'])

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // The RAW filter path reached `in` with no element-split: the whole list was
  // encrypted as one equality term, so the request parsed and returned zero
  // rows. A mock records the emitted operand and cannot tell that apart from a
  // correct one — only a real server proves the predicate selects `ada`.
  it('matches an encrypted in-list through the raw filter() path', async () => {
    const { data, error } = await from()
      .select('row_key')
      .filter('nickname', 'in', ['ada', 'nobody'])

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // The same call must still EXCLUDE a row whose value is absent from the list.
  // Without this, a filter that matched everything would pass the test above.
  it('excludes a row whose value is absent from a raw in-list', async () => {
    const { data, error } = await from()
      .select('row_key')
      .filter('nickname', 'in', ['nobody', 'someone'])

    expect(error).toBeNull()
    expect(data).toEqual([])
  })

  // A PostgREST list literal cannot be encrypted element-wise; the adapter
  // refuses it rather than emit a filter that silently matches nothing.
  it('rejects a raw in-list passed as a PostgREST list literal', async () => {
    const { error } = await from()
      .select('row_key')
      .filter('nickname', 'in', '("ada","nobody")')

    expect(error?.message).toMatch(/requires an array of values/)
  })

  // A plaintext column keeps postgrest-js's own encoding, untouched. Passing a
  // list LITERAL is the only form its raw `.filter()` renders correctly.
  it('leaves a raw in-list literal on a plaintext column to postgrest-js', async () => {
    const { data, error } = await from()
      .select('row_key')
      .filter('row_key', 'in', '("ada","nobody")')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // Pins what we did NOT change. postgrest-js renders `.filter(col,'in',[…])`
  // as an unparenthesized `in.ada,nobody`, which PostgREST rejects with
  // PGRST100 — true of every plaintext column, before this change and after.
  // The encrypted path cannot inherit that: it must take an array (nothing else
  // can be encrypted element-wise) and so builds the literal itself. Asserting
  // the asymmetry keeps a future "helpfully format plaintext arrays too" from
  // landing unnoticed as a behaviour change.
  it('does not rescue a raw in-list ARRAY on a plaintext column', async () => {
    const { error } = await from()
      .select('row_key')
      .filter('row_key', 'in', ['ada', 'nobody'])

    expect(error?.code).toBe('PGRST100')
    expect(error?.details).toContain('expecting "("')
  })

  // A caller-chosen alias keys the row by neither the property nor the DB name.
  // PostgREST has to parse `ts:created_at::jsonb` and key the row `ts`, and the
  // adapter has to follow that alias back to the column's `cast_as` to rebuild
  // the `Date`. Both halves are only observable against a real server.
  it('reconstructs a Date under a caller-chosen select alias', async () => {
    const { data, error } = await from()
      .select('row_key, ts:createdAt')
      .eq('row_key', 'ada')

    expect(error).toBeNull()
    expect(data).toHaveLength(1)
    expect(data[0].ts).toBeInstanceOf(Date)
    expect((data[0].ts as Date).toISOString()).toBe(ADA_CREATED.toISOString())
  })

  it('updates and deletes through encrypted WHERE operands', async () => {
    const updated = await from()
      .update({ note: 'changed' })
      .eq('nickname', 'ada')
    expect(updated.error).toBeNull()

    const deleted = await from().delete().eq('nickname', 'ada')
    expect(deleted.error).toBeNull()

    const { data } = await from().select('row_key')
    expect(data).toEqual([])
  })
})
