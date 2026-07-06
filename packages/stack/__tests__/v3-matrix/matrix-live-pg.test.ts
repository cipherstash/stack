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
 *   - eq      (any `unique`/`hm` domain):   `eql_v3.eq_term`    + `hmac_256`
 *   - ord     (any `ore`/`ob` domain):      `eql_v3.ord_term`   + `ore_block_256`.
 *     Pure-ORE domains (numeric/date `*_ord`/`*_ord_ore`) are queried with
 *     `queryType:'equality'` — the equality-via-ORE path Part A fixed — because
 *     `ob` is their only index and they have no `eq_term` at all in the real
 *     `eql_v3` SQL (verified against the fixture). Text order domains carry BOTH
 *     `hm` and `ob`, so they run the eq proof AND the ord proof; their `ob` term
 *     is built with `queryType:'orderAndRange'` (equality would resolve to `hm`).
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
import { describeLivePg, LIVE_EQL_V3_PG_ENABLED } from '../helpers/live-gate'
import {
  type DomainSpec,
  type EqlV3TypeName,
  typedEntries,
  V3_MATRIX,
} from './catalog'

// Previously force-skipped (CI run 28569708268, PR #540): `beforeAll` crashed
// with `PostgresError: invalid input syntax for type json` on the dynamic
// 35-column INSERT. Root cause was a postgres.js serialization gap — a bare
// ciphertext object stringified to `"[object Object]"` — now fixed by wrapping
// every INSERT param in `sql.json(...)` (see `beforeAll`; the fix landed right
// after the skip and the skip was simply left stale). Re-enabled here as an
// ordinary credential-gated suite: it runs in CI (which supplies DATABASE_URL +
// CS_* creds) and self-skips locally when they are absent.

const databaseUrl = process.env.DATABASE_URL
const sql = LIVE_EQL_V3_PG_ENABLED
  ? postgres(databaseUrl as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

const TABLE_NAME = 'v3_matrix_live_pg'
const TEST_RUN_ID = `matrix-live-pg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

/** `eql_v3.int4_ord` -> `int4_ord`: a valid, unique Postgres column name. */
const slug = (t: EqlV3TypeName): string => t.replace('eql_v3.', '')

const expectDecryptedStorageValue = (
  decrypted: unknown,
  expected: unknown,
): void => {
  if (expected instanceof Date) {
    expect(typeof decrypted).toBe('string')
    expect(new Date(decrypted)).toEqual(expected)
    return
  }

  expect(decrypted).toBe(expected)
}

const domains = typedEntries(V3_MATRIX)

const columns = Object.fromEntries(
  domains.map(([t, spec]) => [slug(t), spec.builder(slug(t))]),
)
const table = encryptedTable(TABLE_NAME, columns as never)

/**
 * Which proofs a domain's configured indexes call for. Unlike a single-kind
 * classifier these lists are NOT mutually exclusive — a domain runs EVERY proof
 * its indexes support:
 *
 * - eq  (`hm`): every domain carrying a `unique` index → `eq_term`/`hmac_256`.
 * - ord (`ob`): every domain carrying an `ore` index   → `ord_term`/`ore_block_256`.
 * - match (`bf`): every domain carrying a `match` index → `match_term`/`bloom_filter`.
 * - storage: a domain with NO index — only the ciphertext round-trip proof.
 *
 * Text order domains (`text_ord`/`text_ord_ore`) carry BOTH `unique` and `ore`,
 * so they appear in `eqDomains` AND `ordDomains` and run both proofs — a
 * wrong-valued `ob` would otherwise slip through an eq-only check (text equality
 * is HMAC-based, so `queryType:'equality'` on them resolves to `hm`, never `ob`;
 * their ord term is built with `queryType:'orderAndRange'` below). `text_search`
 * also carries all three indexes but is deliberately exercised by the match
 * proof ALONE — its distinguishing, richest capability and the one canonical
 * example per tier — so it is excluded from the eq/ord lists via `!match`.
 */
const hasIndex = (
  indexes: DomainSpec['indexes'],
  key: 'unique' | 'ore' | 'match',
): boolean => Boolean((indexes ?? {})[key])

const matchDomains = domains.filter(([, spec]) =>
  hasIndex(spec.indexes, 'match'),
)
const eqDomains = domains.filter(
  ([, spec]) =>
    hasIndex(spec.indexes, 'unique') && !hasIndex(spec.indexes, 'match'),
)
const ordDomains = domains.filter(
  ([, spec]) =>
    hasIndex(spec.indexes, 'ore') && !hasIndex(spec.indexes, 'match'),
)
const storageDomains = domains.filter(
  ([, spec]) =>
    !hasIndex(spec.indexes, 'unique') &&
    !hasIndex(spec.indexes, 'ore') &&
    !hasIndex(spec.indexes, 'match'),
)
const textOreDomains = domains.filter(
  ([t]) =>
    t === 'eql_v3.text_ord_ore' ||
    t === 'eql_v3.text_ord' ||
    t === 'eql_v3.text_search',
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
    // `sql.json(...)` (not the bare ciphertext object): postgres.js only infers
    // an explicit wire type for `Parameter`/`Date`/`Uint8Array`/boolean/bigint —
    // a plain object falls through to `'' + x` (`Bind()` in
    // postgres/src/connection.js), i.e. the literal string `"[object Object]"`,
    // which Postgres rejects as invalid JSON before the domain cast ever runs.
    const values = domains.map(([t]) => sql.json(enc[slug(t)] as never))
    const [row] = await sql.unsafe<Row[]>(
      `INSERT INTO ${TABLE_NAME} (test_run_id, ${colNames.join(', ')})
       VALUES ($1, ${casts.join(', ')})
       RETURNING id`,
      [TEST_RUN_ID, ...values],
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
    // Pure-ORE domains (numeric/date) answer equality via ORE, so
    // `queryType:'equality'` resolves to the `ob` term — the exact
    // equality-via-ORE path Part A fixed. Text order domains ALSO carry `hm`,
    // where `equality` resolves to HMAC by the shared `unique > … > ore`
    // priority; force `orderAndRange` there so the term still carries the `ob`
    // this proof extracts with `ore_block_256`.
    const queryType = hasIndex(spec.indexes, 'unique')
      ? 'orderAndRange'
      : 'equality'
    ordTerms[slug(t)] = unwrapResult(
      await client.encryptQuery(
        spec.samples[0] as never,
        {
          table,
          column: columnRef(t),
          queryType,
        } as never,
      ),
    )
  }
  // text_match/text_search: query a substring of whichever seeded sample
  // contains "ada". `text_match` still uses the shared TEXT_S with an empty row
  // A, while `text_search` uses non-empty TEXT_ORE_S to satisfy its `ob` check.
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
      [TEST_RUN_ID, sql.json(eqTerms[col] as never)],
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
      [TEST_RUN_ID, sql.json(ordTerms[col] as never)],
    )
    expect(rows.map((r) => r.id)).toEqual([idA])
  })

  it.each(
    textOreDomains,
  )('%s: encrypted empty string is rejected by the Postgres domain', async (eqlType) => {
    const col = slug(eqlType)
    const column = (table as unknown as Record<string, unknown>)[col] as never
    const encrypted = unwrapResult(
      await client.encrypt('', {
        table: table as never,
        column,
      }),
    )

    await expect(
      sql.unsafe(`SELECT $1::${eqlType}`, [sql.json(encrypted as never)]),
    ).rejects.toThrow(/violates check constraint/)
  })

  it.each(
    matchDomains,
  )('%s: match_term/bloom_filter selects the row containing "ada"', async (eqlType, spec) => {
    const col = slug(eqlType)
    const expectedId = String(spec.samples[0]).includes('ada') ? idA : idB
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.match_term("${col}") @> eql_v3.bloom_filter($2::jsonb)`,
      [TEST_RUN_ID, sql.json(matchTerms[col] as never)],
    )
    expect(rows.map((r) => r.id)).toEqual([expectedId])
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
    expectDecryptedStorageValue(decrypted, expected)
  })
})
