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
 * has at least two), and per domain one proof per query permutation its indexes
 * support — proving each selects the expected row and not the other. Beyond the
 * per-capability proofs below, every applicable domain also exercises the public
 * two-arg negation/containment/range functions: `eql_v3.neq` (eq domains),
 * `eql_v3.contained_by` (match domains), and explicit two-bound `eql_v3.gte`+`lte`
 * with strict `gt`+`lt` (ordering domains), plus a strict pairwise-`lt` ordering
 * proof. Queries use the supported EQL v3 API: a FULL encrypted
 * operand (`client.encrypt`, same payload as storage) compared against the
 * column with a public two-arg `eql_v3.*(col, operand::jsonb)` function. (The
 * old `encryptQuery` scalar-term path is unsupported in protect-ffi 0.28 —
 * `EQL_V3_QUERY_UNSUPPORTED` — and the operand carries every index term, so the
 * SQL function per proof, not a `queryType`, selects which term is compared.)
 * Dispatch mirrors the priority `resolveIndexType` uses (match > unique > ore):
 *   - match   (text_match, text_search):    `eql_v3.contains(col, operand)`
 *   - eq      (any `unique` domain):        `eql_v3.eq(col, operand)`
 *   - ord     (any `ore` domain):           ORE range `eql_v3.gte(col,op) AND
 *     eql_v3.lte(col,op)`. Pure-ORE numeric/date `*_ord`/`*_ord_ore` domains
 *     have no `hm` term, so `eql_v3.eq` there resolves to `ord_term` — that IS
 *     the equality-via-ORE proof — while text order domains carry BOTH `hm` and
 *     `ob`, so they use the explicit range to exercise `ob` (a bare `eql_v3.eq`
 *     would silently compare `hm`). Text order domains also run the eq proof.
 *   - storage (no index): no query is possible; proves the ciphertext, cast to
 *     THIS SPECIFIC Postgres domain type, survives a real INSERT/SELECT and
 *     still decrypts — the one thing the FFI-only round-trip can't show.
 *
 * In addition, EVERY ORE ordering domain (every `ore`-indexed domain: all
 * `_ord`/`_ord_ore` numeric/date/timestamp domains plus `text_ord`,
 * `text_ord_ore` and `text_search`) gets a STRICT total-order proof. Its
 * distinct sample values are each seeded as their own row (under a separate
 * `ORDER_RUN_ID`, so the two-row proofs above are unaffected) and the boolean
 * `eql_v3.lt` comparison is used — via a self cross-join ranking — to prove the
 * ORE order reproduces the full plaintext order (a<b<c<d where the domain has
 * that many distinct samples). This strengthens the `ord` proof above, which
 * only shows equality-via-ORE / a single degenerate range. The comparison
 * operator (NOT `ORDER BY eql_v3.ord_term(col)`) is used deliberately: it is
 * ORE-correct on both superuser (CI) and non-superuser (local) Postgres.
 */
import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptionV3, encryptedTable } from '@/encryption/v3'
import { unwrapResult } from '../fixtures'
import { installEqlV3IfNeeded } from '../helpers/eql-v3'
import { describeLivePg, LIVE_EQL_V3_PG_ENABLED } from '../helpers/live-gate'
import {
  type DomainSpec,
  type EqlV3TypeName,
  eqlTypeSlug as slug,
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
): boolean => Boolean(indexes?.[key])

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
    t === 'public.text_ord_ore' ||
    t === 'public.text_ord' ||
    t === 'public.text_search',
)

// EVERY ORE ordering domain: all `_ord`/`_ord_ore` numeric/date/timestamp
// domains PLUS the three text order domains (`text_ord`, `text_ord_ore`,
// `text_search`) — i.e. every domain carrying an `ore` index. `text_search`
// is intentionally INCLUDED here (unlike `ordDomains`, which excludes it so
// its canonical proof stays the match one): strict ORE ordering is a real
// capability of that domain and gets its own proof below.
const orderingDomains = domains.filter(([, spec]) =>
  hasIndex(spec.indexes, 'ore'),
)

// The number of separate ordering rows to seed: the widest ordering domain's
// distinct sample count (numeric domains carry 4; text carries 3; date/
// timestamp carry 2). Narrower domains reuse their last sample in the extra
// rows (harmless — each per-domain proof only reads its own first N rows).
const MAX_ORDER_ROWS = Math.max(
  ...orderingDomains.map(([, spec]) => spec.samples.length),
)

/** Plaintext ordering used to derive the EXPECTED ORE order per domain.
 * Dates compare by instant, numbers and bigints numerically, strings by code
 * point (ORE text order is byte order, which matches JS `<` for the ASCII
 * samples here). */
const comparePlaintext = (a: unknown, b: unknown): number => {
  if (a instanceof Date && b instanceof Date) return a.getTime() - b.getTime()
  if (typeof a === 'number' && typeof b === 'number') return a - b
  // `bigint` samples (BIGINT_S) must compare numerically, not lexicographically:
  // String(-42n) < String(-9223372036854775808n) is TRUE ('-4' < '-9') yet
  // -42 > -9.2e18. Without this branch the two bigint ORE domains fall through
  // to the string compare below and the expected order is numerically wrong,
  // even though the ORE ciphertext order is correct. (`a - b` is a bigint, so
  // it can't be returned to Array.sort — use the comparison form.)
  if (typeof a === 'bigint' && typeof b === 'bigint')
    return a < b ? -1 : a > b ? 1 : 0
  const sa = String(a)
  const sb = String(b)
  return sa < sb ? -1 : sa > sb ? 1 : 0
}

type Row = { id: number }

let client: Awaited<ReturnType<typeof EncryptionV3>>
let idA: number
let idB: number
// Separate run id for the multi-row ordering rows. Kept DISTINCT from
// TEST_RUN_ID so the existing eq/match/storage/ord proofs (which filter on
// TEST_RUN_ID and expect exactly the two idA/idB rows) never see these extra
// rows — e.g. the `text_match` "contains ada" proof would otherwise also match
// a downcased 'Ada Lovelace' row.
const ORDER_RUN_ID = `${TEST_RUN_ID}-order`
// Row ids of the seeded ordering rows, in sample-index order: orderIds[i]
// holds `samples[min(i, L-1)]` for every domain, so orderIds[0..L-1] map 1:1
// to a domain's distinct samples[0..L-1].
let orderIds: number[] = []
// Query terms, pre-encrypted once in `beforeAll` (not per `it.each` case).
const eqTerms: Record<string, unknown> = {}
const ordTerms: Record<string, unknown> = {}
const matchTerms: Record<string, unknown> = {}
// Full operand for each match domain's `samples[0]` value (NOT the 'ada'
// substring in `matchTerms`) — used by the `contained_by` proof.
const containedByTerms: Record<string, unknown> = {}
// Full operand for each ordering domain's distinct samples[0..L-1], reused from
// the already-encrypted `ORDER_RUN_ID` rows (no extra encryption) — used by the
// two-bound range / strict gt-lt proof.
const orderOperands: Record<string, unknown[]> = {}

beforeAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return

  await installEqlV3IfNeeded(sql)
  client = await EncryptionV3({ schemas: [table] as never })

  const columnDefs = domains
    .map(([t]) => `"${slug(t)}" ${t} NOT NULL`)
    .join(',\n    ')

  // DROP first: the table is created with IF NOT EXISTS and cleaned up by row
  // DELETE only, so a table left by an earlier local run keeps its OLD column
  // domain types across the `eql_v3.* -> public.*` / `timestamptz -> timestamp`
  // renames — silently testing against a stale schema. Harmless in CI (fresh
  // Postgres each run); load-bearing for reliable local reruns.
  await sql.unsafe(`DROP TABLE IF EXISTS ${TABLE_NAME}`)
  await sql.unsafe(`
    CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      test_run_id TEXT NOT NULL,
      ${columnDefs}
    )
  `)

  // Model rows for the ordering proofs: row i carries `samples[min(i, L-1)]`
  // for every domain (`L` = that domain's sample count). Rows 0/1 double as the
  // classic two-row seed (samples[0]/samples[1]) reused by the existing proofs;
  // rows 2..MAX_ORDER_ROWS-1 give the extra distinct values numeric/text
  // ordering domains need for a full a<b<c(<d). Encrypted in ONE
  // bulkEncryptModels batch, then the same ciphertexts are inserted twice: rows
  // 0/1 under TEST_RUN_ID (idA/idB) for the existing proofs, and all rows under
  // ORDER_RUN_ID for the ordering proofs.
  const models = Array.from({ length: MAX_ORDER_ROWS }, (_, i) => {
    const row: Record<string, unknown> = {}
    for (const [t, spec] of domains) {
      row[slug(t)] = spec.samples[Math.min(i, spec.samples.length - 1)]
    }
    return row
  })

  const encModels = unwrapResult(
    await client.bulkEncryptModels(models as never, table as never),
  ) as Array<Record<string, unknown>>

  const colNames = domains.map(([t]) => `"${slug(t)}"`)
  const insertRow = async (
    enc: Record<string, unknown>,
    runId: string,
  ): Promise<number> => {
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
      [runId, ...values],
    )
    return row.id
  }
  idA = await insertRow(encModels[0], TEST_RUN_ID)
  idB = await insertRow(encModels[1], TEST_RUN_ID)
  orderIds = []
  for (const enc of encModels) {
    orderIds.push(await insertRow(enc, ORDER_RUN_ID))
  }

  const columnRef = (t: EqlV3TypeName) =>
    (table as unknown as Record<string, unknown>)[slug(t)] as never

  // Query operands are FULL encrypted payloads — the same thing `client.encrypt`
  // produces for storage — NOT `encryptQuery` terms. protect-ffi 0.28 has no v3
  // scalar query wire shape (`encryptQuery` throws EQL_V3_QUERY_UNSUPPORTED), so
  // the supported path is to encrypt the search value as an operand and compare
  // it with the public two-arg `eql_v3.*(col, operand::jsonb)` functions in SQL.
  // The full operand carries every index term, so `queryType` dispatch is gone —
  // the SQL function chosen per proof (eq / gte+lte / contains) selects which
  // term the comparison uses. `opts` is cast `as never` because these columns
  // are built dynamically (`Object.fromEntries`) and carry no static type.
  const encryptOperand = async (t: EqlV3TypeName, value: unknown) =>
    unwrapResult(
      await client.encrypt(
        value as never,
        {
          table,
          column: columnRef(t),
        } as never,
      ),
    )
  for (const [t, spec] of eqDomains) {
    eqTerms[slug(t)] = await encryptOperand(t, spec.samples[0])
  }
  for (const [t, spec] of ordDomains) {
    ordTerms[slug(t)] = await encryptOperand(t, spec.samples[0])
  }
  // text_match/text_search: query the substring "ada", present only in the
  // seeded sample of exactly one row per domain.
  for (const [t] of matchDomains) {
    matchTerms[slug(t)] = await encryptOperand(t, 'ada')
  }
  // `contained_by` operand = the FULL `samples[0]` value (row idA). Its token
  // set equals idA's, so idA is contained_by it, while idB (`samples[1]`) has
  // tokens the operand lacks. Reuse the already-encrypted `encModels[0]`.
  for (const [t] of matchDomains) {
    containedByTerms[slug(t)] = encModels[0][slug(t)]
  }
  // Range-bound operands: the full operand for each distinct sample of an
  // ordering domain, taken straight from the encrypted `ORDER_RUN_ID` rows
  // (`encModels[i]` ↔ `orderIds[i]` ↔ `samples[i]`). No extra encryption.
  for (const [t, spec] of orderingDomains) {
    orderOperands[slug(t)] = encModels
      .slice(0, spec.samples.length)
      .map((m) => m[slug(t)])
  }
}, 120000)

afterAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return
  await sql.unsafe(`DELETE FROM ${TABLE_NAME} WHERE test_run_id = ANY($1)`, [
    [TEST_RUN_ID, ORDER_RUN_ID],
  ])
  await sql.end()
}, 30000)

describeLivePg('v3 matrix live Postgres coverage (all 35 domains)', () => {
  it.each(
    eqDomains,
  )('%s: eql_v3.eq(col, operand) selects the exact row', async (eqlType) => {
    const col = slug(eqlType)
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.eq("${col}", $2::jsonb)`,
      [TEST_RUN_ID, sql.json(eqTerms[col] as never)],
    )
    expect(rows.map((r) => r.id)).toEqual([idA])
  })

  it.each(
    eqDomains,
  )('%s: eql_v3.neq(col, operand) excludes the matching row', async (eqlType) => {
    const col = slug(eqlType)
    // Operand encrypts `samples[0]` (row idA). `neq` selects every row whose
    // value differs, i.e. row idB (`samples[1]`) only — idA is excluded.
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.neq("${col}", $2::jsonb)`,
      [TEST_RUN_ID, sql.json(eqTerms[col] as never)],
    )
    expect(rows.map((r) => r.id)).toEqual([idB])
  })

  it.each(
    ordDomains,
  )('%s: equality-via-ORE selects the exact row', async (eqlType, spec) => {
    const col = slug(eqlType)
    // The proof must exercise the ORDER (`ob`) term, not equality. On text order
    // domains (`text_ord`/`text_ord_ore`, which carry BOTH `unique` and `ore`)
    // `eql_v3.eq` compares the `hm` term, so pin the ORE term with a degenerate
    // range `col >= operand AND col <= operand` (both `ord_term`-based) — it
    // selects the equal row via ORE. Pure-ORE numeric/date domains have no `hm`,
    // so `eql_v3.eq` resolves to `ord_term`: that IS the equality-via-ORE proof.
    const predicate = hasIndex(spec.indexes, 'unique')
      ? `eql_v3.gte("${col}", $2::jsonb) AND eql_v3.lte("${col}", $2::jsonb)`
      : `eql_v3.eq("${col}", $2::jsonb)`
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND ${predicate}`,
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
  )('%s: eql_v3.contains selects the row containing "ada"', async (eqlType, spec) => {
    const col = slug(eqlType)
    const expectedId = String(spec.samples[0]).includes('ada') ? idA : idB
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.contains("${col}", $2::jsonb)`,
      [TEST_RUN_ID, sql.json(matchTerms[col] as never)],
    )
    expect(rows.map((r) => r.id)).toEqual([expectedId])
  })

  it.each(
    matchDomains,
  )('%s: eql_v3.contained_by selects the row whose tokens the operand covers', async (eqlType) => {
    const col = slug(eqlType)
    // `contained_by(col, operand)` (`col <@ operand`) is true when the column's
    // bloom tokens are a subset of the operand's. The operand encrypts row idA's
    // full `samples[0]` value, so idA (equal token set) is contained_by it, while
    // idB (`samples[1]`) carries tokens the operand lacks and is excluded. This is
    // the dual of the `contains`/`@>` proof above.
    const rows = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND eql_v3.contained_by("${col}", $2::jsonb)`,
      [TEST_RUN_ID, sql.json(containedByTerms[col] as never)],
    )
    expect(rows.map((r) => r.id)).toEqual([idA])
  })

  it.each(
    orderingDomains,
  )('%s: ORE pairwise-lt reproduces plaintext order across all distinct samples', async (eqlType, spec) => {
    // STRICT ordering proof: seed each of a domain's distinct sample values as
    // its OWN row (orderIds[0..L-1] ↔ samples[0..L-1]) and prove the ORE
    // comparison reproduces the FULL plaintext order (a<b<c<d where available),
    // not just equality-via-ORE or a single 2-row range.
    //
    // The order is reconstructed with the boolean `eql_v3.lt` comparison
    // operator (a self cross-join counting, per row, how many rows it is
    // strictly-less-than → its ascending rank). This is ENVIRONMENT-INDEPENDENT:
    // it is ORE-correct on both a superuser Postgres (CI) and a non-superuser
    // one (typical local dev), unlike `ORDER BY eql_v3.ord_term(col)`, whose
    // ORE-aware btree opclass is superuser-gated and silently falls back to
    // raw-byte record order on managed installs. See
    // docs/eql-v3-ord-term-ordering-defect.md.
    const col = slug(eqlType)
    const L = spec.samples.length
    const ids = orderIds.slice(0, L)

    // Expected ascending order: sort the distinct samples by plaintext, mapping
    // each to the id of the row that carries it (samples[i] -> orderIds[i]).
    const expectedAscending = spec.samples
      .map((value, i) => ({ value, id: ids[i] }))
      .sort((x, y) => comparePlaintext(x.value, y.value))
      .map((entry) => entry.id)

    const pairs = await sql.unsafe<
      Array<{ a: number; b: number; lt: boolean }>
    >(
      `SELECT x.id AS a, y.id AS b, eql_v3.lt(x."${col}", y."${col}") AS lt
         FROM ${TABLE_NAME} x
         CROSS JOIN ${TABLE_NAME} y
        WHERE x.test_run_id = $1
          AND y.test_run_id = $1
          AND x.id = ANY($2)
          AND y.id = ANY($2)
          AND x.id <> y.id`,
      [ORDER_RUN_ID, ids],
    )

    const lessThanCount = new Map<number, number>(ids.map((id) => [id, 0]))
    for (const pair of pairs) {
      if (pair.lt) {
        lessThanCount.set(pair.a, (lessThanCount.get(pair.a) ?? 0) + 1)
      }
    }

    // Ascending rank = strictly-less-than count, descending (the smallest value
    // is < every other row, so it has the highest count and sorts first).
    const derivedAscending = [...ids].sort(
      (a, b) => (lessThanCount.get(b) ?? 0) - (lessThanCount.get(a) ?? 0),
    )

    // Sanity: distinct samples must yield distinct ranks 0..L-1 (a strict total
    // order), otherwise the ORE comparison collapsed two values together.
    expect(new Set(lessThanCount.values()).size).toBe(L)
    expect(derivedAscending).toEqual(expectedAscending)
  })

  it.each(
    orderingDomains,
  )('%s: eql_v3.gte/lte (inclusive) and gt/lt (exclusive) bound the ORE range', async (eqlType, spec) => {
    // Explicit two-bound ORE range over the distinct-sample rows: `[lo, hi]`
    // spans the whole set, so gte+lte must select ALL of them and strict gt+lt
    // must select only the interior (excluding the lo and hi rows). Bounds are
    // the plaintext-min/max samples; membership is compared to the plaintext
    // order. Uses the boolean comparison operators (ORE-correct on superuser AND
    // non-superuser Postgres) — never `ORDER BY ord_term`. For L=2 domains
    // (date/timestamp) the interior is empty: a valid exclusive-bound boundary.
    const col = slug(eqlType)
    const L = spec.samples.length
    const ids = orderIds.slice(0, L)
    const operands = orderOperands[col]

    const sortedIdx = spec.samples
      .map((value, i) => ({ value, i }))
      .sort((a, b) => comparePlaintext(a.value, b.value))
      .map((entry) => entry.i)
    const lo = sql.json(operands[sortedIdx[0]] as never)
    const hi = sql.json(operands[sortedIdx[L - 1]] as never)

    // Inclusive [lo, hi] → every distinct-sample row.
    const inclusive = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND id = ANY($2)
           AND eql_v3.gte("${col}", $3::jsonb)
           AND eql_v3.lte("${col}", $4::jsonb)`,
      [ORDER_RUN_ID, ids, lo, hi],
    )
    expect(new Set(inclusive.map((r) => r.id))).toEqual(new Set(ids))

    // Exclusive (lo, hi) via strict gt/lt → strictly-interior rows only.
    const interiorIds = sortedIdx.slice(1, L - 1).map((i) => ids[i])
    const exclusive = await sql.unsafe<Row[]>(
      `SELECT id FROM ${TABLE_NAME}
         WHERE test_run_id = $1
           AND id = ANY($2)
           AND eql_v3.gt("${col}", $3::jsonb)
           AND eql_v3.lt("${col}", $4::jsonb)`,
      [ORDER_RUN_ID, ids, lo, hi],
    )
    expect(new Set(exclusive.map((r) => r.id))).toEqual(new Set(interiorIds))
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
