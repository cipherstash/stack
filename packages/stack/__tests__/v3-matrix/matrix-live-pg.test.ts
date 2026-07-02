/**
 * Live Postgres coverage for ALL 35 v3 domains — one query-correctness proof
 * per domain, dispatched by capability tier, against a real installed eql_v3
 * extension.
 *
 * `matrix-live.test.ts` proves every domain round-trips through live FFI
 * ciphertext, but never touches SQL. `schema-v3-pg.test.ts` proves real SQL
 * query behaviour, but only for 4 hand-picked domains. Neither is redundant
 * with this file: the equality-via-ORE fix (`infer-index-type.ts`) shows an
 * SDK-side bug can hide behind a clean FFI round-trip and only surface
 * against real Postgres — defence in depth means every domain gets that
 * proof, not just a representative few. This file also doubles as one
 * canonical, runnable example per capability tier of how to actually query
 * each kind of v3 domain in SQL — useful reference for engineers and agents
 * writing new domain-consuming code.
 *
 * ONE mega table (all 35 domains, one column each, like `matrix-live.test.ts`),
 * two seeded rows (`samples[0]` / `samples[1]` from the catalog — every domain
 * has at least two), one query per domain proving it selects the expected row
 * and not the other. Dispatch mirrors the priority `resolveIndexType` itself
 * uses (match > unique > ore > none):
 *   - match   (text_match, text_search):    `eql_v3.match_term` + `bloom_filter`
 *   - eq      (*_eq domains):               `eql_v3.eq_term`    + `hmac_256`
 *   - ord     (*_ord / *_ord_ore domains):  `eql_v3.ord_term`   + `ore_block_256`,
 *     queried with `queryType:'equality'` — the exact path Part A fixed. Most
 *     ord-tier domains (all but text) have no `eq_term` at all in the real
 *     `eql_v3` SQL (verified against the fixture), so this is not a stylistic
 *     choice: it is the only equality path that exists for them.
 *   - storage (no index): no query is possible; proves the ciphertext, cast to
 *     THIS SPECIFIC Postgres domain type, survives a real INSERT/SELECT and
 *     still decrypts — the one thing the FFI-only round-trip can't show.
 */
import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3, encryptedTable } from '@/encryption/v3'
import { unwrapResult } from '../fixtures'
import { installEqlV3IfNeeded } from '../helpers/eql-v3'
import {
  type DomainSpec,
  type EqlV3TypeName,
  typedEntries,
  V3_MATRIX,
} from './catalog'

const LIVE_EQL_V3_PG_ENABLED = Boolean(
  process.env.DATABASE_URL &&
    process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)
const describeLivePg = LIVE_EQL_V3_PG_ENABLED ? describe : describe.skip

const databaseUrl = process.env.DATABASE_URL
const sql = LIVE_EQL_V3_PG_ENABLED
  ? postgres(databaseUrl as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

const TABLE_NAME = 'v3_matrix_live_pg'
const TEST_RUN_ID = `matrix-live-pg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

/** `eql_v3.int4_ord` -> `int4_ord`: a valid, unique Postgres column name. */
const slug = (t: EqlV3TypeName): string => t.replace('eql_v3.', '')

const domains = typedEntries(V3_MATRIX)

const columns = Object.fromEntries(
  domains.map(([t, spec]) => [slug(t), spec.builder(slug(t))]),
)
const table = encryptedTable(TABLE_NAME, columns as never)

/**
 * The one proof each domain's configured indexes call for — mirrors the
 * priority `resolveIndexType`/`inferIndexType` themselves use: match wins over
 * unique wins over ore. `text_search` carries all three but gets the match
 * proof (its distinguishing, richest capability); the plain `*_eq` domains get
 * the eq proof; every `*_ord`/`*_ord_ore` domain (including the text ones,
 * which also have an `eq_term` but are queried the same way as their
 * non-text siblings for consistency) gets the equality-via-ORE proof.
 */
type ProofKind = 'match' | 'eq' | 'ord' | 'storage'
function proofKindFor(indexes: DomainSpec['indexes']): ProofKind {
  const idx = indexes ?? {}
  if (idx.match) return 'match'
  if (idx.unique) return 'eq'
  if (idx.ore) return 'ord'
  return 'storage'
}

const matchDomains = domains.filter(
  ([, spec]) => proofKindFor(spec.indexes) === 'match',
)
const eqDomains = domains.filter(
  ([, spec]) => proofKindFor(spec.indexes) === 'eq',
)
const ordDomains = domains.filter(
  ([, spec]) => proofKindFor(spec.indexes) === 'ord',
)
const storageDomains = domains.filter(
  ([, spec]) => proofKindFor(spec.indexes) === 'storage',
)

type Row = { id: number }

let client: Awaited<ReturnType<typeof EncryptionV3>>
let idA: number
let idB: number
// Query terms, pre-encrypted once in `beforeAll` (not per `it.each` case).
const eqTerms: Record<string, unknown> = {}
const ordTerms: Record<string, unknown> = {}
const matchTerms: Record<string, unknown> = {}

beforeAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return

  await installEqlV3IfNeeded(sql)
  client = await EncryptionV3({ schemas: [table] as never })

  const columnDefs = domains
    .map(([t]) => `"${slug(t)}" ${t} NOT NULL`)
    .join(',\n    ')

  await sql.unsafe(`
    CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      test_run_id TEXT NOT NULL,
      ${columnDefs}
    )
  `)

  // Two model rows: row A carries samples[0], row B carries samples[1], for
  // every domain — every catalog `samples` array has at least two entries.
  const rowA: Record<string, unknown> = {}
  const rowB: Record<string, unknown> = {}
  for (const [t, spec] of domains) {
    rowA[slug(t)] = spec.samples[0]
    rowB[slug(t)] = spec.samples[1]
  }

  const [encA, encB] = unwrapResult(
    await client.bulkEncryptModels([rowA, rowB] as never, table as never),
  ) as Array<Record<string, unknown>>

  const colNames = domains.map(([t]) => `"${slug(t)}"`)
  const insertRow = async (enc: Record<string, unknown>): Promise<number> => {
    const casts = domains.map(([t], i) => `$${i + 2}::${t}`)
    const values = domains.map(([t]) => enc[slug(t)]) as never[]
    const [row] = await sql.unsafe<Row[]>(
      `INSERT INTO ${TABLE_NAME} (test_run_id, ${colNames.join(', ')})
       VALUES ($1, ${casts.join(', ')})
       RETURNING id`,
      [TEST_RUN_ID, ...values] as never[],
    )
    return row.id
  }
  idA = await insertRow(encA)
  idB = await insertRow(encB)

  const columnRef = (t: EqlV3TypeName) =>
    (table as unknown as Record<string, unknown>)[slug(t)] as never

  // The full `opts` object (not just `column`) is cast `as never`: `encryptQuery`
  // derives its allowed `queryType` union FROM the column's type
  // (`QueryTypesForColumn<C>`), so a `never`-typed `column` alone collapses
  // `queryType` to `undefined` rather than widening it — this table's columns
  // are built dynamically (`Object.fromEntries`), so none of them carry a
  // statically-known type for `encryptQuery` to key off in the first place.
  for (const [t, spec] of eqDomains) {
    eqTerms[slug(t)] = unwrapResult(
      await client.encryptQuery(
        spec.samples[0] as never,
        {
          table,
          column: columnRef(t),
          queryType: 'equality',
        } as never,
      ),
    )
  }
  for (const [t, spec] of ordDomains) {
    ordTerms[slug(t)] = unwrapResult(
      await client.encryptQuery(
        spec.samples[0] as never,
        {
          table,
          column: columnRef(t),
          queryType: 'equality',
        } as never,
      ),
    )
  }
  // text_match/text_search: query a substring of row B's sample. Row A's
  // shared `TEXT_S[0]` is `''` — a degenerate containment target — so the
  // match proof targets row B instead of the usual row A.
  for (const [t] of matchDomains) {
    matchTerms[slug(t)] = unwrapResult(
      await client.encryptQuery(
        'ada' as never,
        {
          table,
          column: columnRef(t),
          queryType: 'freeTextSearch',
        } as never,
      ),
    )
  }
}, 120000)

afterAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return
  await sql.unsafe(`DELETE FROM ${TABLE_NAME} WHERE test_run_id = $1`, [
    TEST_RUN_ID,
  ])
  await sql.end()
}, 30000)

describeLivePg('v3 matrix live Postgres coverage (all 35 domains)', () => {
  it.each(
    eqDomains,
  )('%s: eq_term/hmac_256 selects the exact row', async (eqlType) => {
    const col = slug(eqlType)
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.eq_term("${col}") = eql_v3.hmac_256($2::jsonb)`,
      [TEST_RUN_ID, eqTerms[col]] as never[],
    )
    expect(rows.map((r) => r.id)).toEqual([idA])
  })

  it.each(
    ordDomains,
  )('%s: ord_term/ore_block_256 equality-via-ORE selects the exact row', async (eqlType) => {
    const col = slug(eqlType)
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.ord_term("${col}") = eql_v3.ore_block_256($2::jsonb)`,
      [TEST_RUN_ID, ordTerms[col]] as never[],
    )
    expect(rows.map((r) => r.id)).toEqual([idA])
  })

  it.each(
    matchDomains,
  )('%s: match_term/bloom_filter selects row B (containing "ada"), not row A', async (eqlType) => {
    const col = slug(eqlType)
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.match_term("${col}") @> eql_v3.bloom_filter($2::jsonb)`,
      [TEST_RUN_ID, matchTerms[col]] as never[],
    )
    expect(rows.map((r) => r.id)).toEqual([idB])
  })

  it.each(
    storageDomains,
  )('%s: ciphertext survives a real INSERT/SELECT and still decrypts', async (eqlType, spec) => {
    const col = slug(eqlType)
    const [row] = await sql.unsafe<Array<{ value: unknown }>>(
      `SELECT "${col}"::jsonb AS value FROM ${TABLE_NAME} WHERE id = $1`,
      [idA],
    )
    const decrypted = unwrapResult(await client.decrypt(row.value as never))
    const expected = spec.samples[0]
    if (expected instanceof Date) {
      expect(decrypted).toEqual(expected)
    } else {
      expect(decrypted).toBe(expected)
    }
  })
})
