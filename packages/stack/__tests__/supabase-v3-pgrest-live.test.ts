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

import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { EncryptedQueryBuilderV3Impl } from '@/supabase/query-builder-v3'
import { SUPABASE_PERMISSIONS_SQL_V3 } from '../../cli/src/installer/grants'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import {
  describeLiveSupabasePgrest,
  LIVE_SUPABASE_PGREST_ENABLED,
} from './helpers/live-gate'
import { makePostgrestClient, reloadSchemaCache } from './helpers/pgrest'
import { narrowedQueryTerm, storageEnvelope } from './helpers/v3-envelope'

const TABLE = 'protect_ci_v3_pgrest'

const sql = LIVE_SUPABASE_PGREST_ENABLED
  ? postgres(process.env.DATABASE_URL as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

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
  { hmac?: boolean; ore?: boolean; bloom?: boolean }
> = {
  email: { hmac: true, ore: true, bloom: true }, // text_search
  nickname: { hmac: true }, // text_eq
  amount: { ore: true }, // integer_ord
  created_at: { ore: true }, // timestamp_ord
  active: {}, // boolean — storage only
}

/** Deterministic 3-gram token set, plus the whole value as one extra token —
 * emulating the default `include_original: true`. That is precisely why a
 * SUBSTRING `like` does not match: the pattern's bloom carries the whole
 * pattern as a token the stored value's bloom lacks (see the class doc on
 * `query-builder-v3.ts`). */
function bloomTokens(value: string): number[] {
  const hash = (s: string) => {
    let h = 2166136261
    for (let i = 0; i < s.length; i++)
      h = ((h ^ s.charCodeAt(i)) * 16777619) >>> 0
    return h % 2048
  }
  const lower = value.toLowerCase()
  const tokens = [hash(lower)] // include_original
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
    ore: terms.ore,
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
  if (!LIVE_SUPABASE_PGREST_ENABLED) return
  await installEqlV3IfNeeded(sql)

  // The shipped Supabase grants — the thing under test, not a hand-rolled
  // approximation. Re-applied after install because the bundle DROPs eql_v3.
  await sql.unsafe(SUPABASE_PERMISSIONS_SQL_V3)
  await sql.unsafe(`DROP TABLE IF EXISTS ${TABLE}`)
  await sql.unsafe(`
    CREATE TABLE ${TABLE} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      email public.text_search,
      nickname public.text_eq,
      amount public.integer_ord,
      created_at public.timestamp_ord,
      active public.boolean,
      note TEXT
    )
  `)
  // The grants block covers eql_v3 objects, not application tables.
  await sql.unsafe(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ${TABLE} TO anon, authenticated`,
  )

  await reloadSchemaCache(sql, TABLE)
}, 180_000)

afterAll(async () => {
  if (!LIVE_SUPABASE_PGREST_ENABLED) return
  await sql.unsafe(`DROP TABLE IF EXISTS ${TABLE}`)
  await sql.end()
})

describeLiveSupabasePgrest('supabase v3 adapter over real PostgREST', () => {
  it('inserts raw envelopes that clear every domain CHECK, as anon', async () => {
    const { error, status } = await from().insert({
      row_key: 'ada',
      email: 'ada@example.com',
      nickname: 'ada',
      amount: 42,
      createdAt: ADA_CREATED,
      active: true,
      note: 'plain',
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
        ore: true,
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

  // `cs` → `@>` on the encrypted domain. This is the load-bearing assertion of
  // the whole suite: the bundle declares
  //   CREATE OPERATOR @> (FUNCTION = eql_v3.contains, LEFTARG = public.text_search,
  //                       RIGHTARG = jsonb)
  // whose body is `match_term(a) @> match_term(b::public.text_search)` — a
  // smallint[] containment of the two BLOOM FILTERS. It is NOT the built-in
  // `jsonb @> jsonb`, which would compare whole envelopes and so could only ever
  // match on an identical ciphertext. The three tests below discriminate: a
  // 3-char needle matches while a 7-char one does not, and neither shares the
  // stored `c`. Only bloom containment explains that.
  //
  // With the default `include_original: true` the needle's bloom carries the
  // WHOLE needle as an extra token, so only an exact-value needle matches.
  // Asserts the DOCUMENTED semantics, not the intuitive ones.
  it('resolves contains() through cs containment for an exact value', async () => {
    const { data, error } = await from()
      .select('row_key')
      .contains('email', 'ada@example.com')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // A needle LONGER than the tokenizer's 3-gram window contributes an
  // `include_original` token no stored trigram can supply, so containment
  // fails. (A needle of exactly 3 characters is the degenerate case: its
  // whole-value token IS a trigram, so `contains('email','ada')` DOES match.)
  // This is the KNOWN-BROKEN substring defect, shared with v3 Drizzle's
  // `contains` and tracked upstream in EQL. Pinned so a fix is a visible change.
  it('does not match a longer substring under include_original', async () => {
    const { data, error } = await from()
      .select('row_key')
      .contains('email', 'example')

    expect(error).toBeNull()
    expect(data).toEqual([])
  })

  it('matches a 3-character substring, the degenerate include_original case', async () => {
    const { data, error } = await from()
      .select('row_key')
      .contains('email', 'ada')

    expect(error).toBeNull()
    expect(data.map((r: { row_key: string }) => r.row_key)).toEqual(['ada'])
  })

  // The reason `like` is gone: `~~` is not defined on public.text_search, so
  // had the adapter emitted it, PostgREST/Postgres would answer 42883. The
  // client-side guard turns that into an actionable error before the round-trip.
  it('refuses like() on an encrypted column rather than emitting an undefined operator', async () => {
    expect(() => from().select('row_key').like('email', 'ada')).toThrow(
      /Use contains\(\)/,
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
