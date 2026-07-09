import 'dotenv/config'
import {
  and,
  asc as drizzleAsc,
  eq as drizzleEq,
  type SQL,
  type SQLWrapper,
} from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptionV3 } from '@/encryption/v3'
import {
  createEncryptionOperatorsV3,
  EncryptionOperatorError,
  extractEncryptionSchemaV3,
  types as v3drizzle,
} from '@/eql/v3/drizzle'
import { makeEqlV3Column } from '@/eql/v3/drizzle/column'
import { installEqlV3IfNeeded } from '../helpers/eql-v3'
import { describeLivePg, LIVE_EQL_V3_PG_ENABLED } from '../helpers/live-gate'
import {
  type DomainSpec,
  type EqlV3TypeName,
  eqlTypeSlug as slug,
  typedEntries,
  V3_MATRIX,
} from '../v3-matrix/catalog'

const url = process.env.DATABASE_URL
const sqlClient = LIVE_EQL_V3_PG_ENABLED
  ? postgres(url as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

const TABLE_NAME = 'protect_ci_v3_drizzle_matrix'
const ACCOUNT_TABLE_NAME = 'protect_ci_v3_drizzle_matrix_accounts'
const RUN = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
const ROW_A = 'row-a'
const ROW_B = 'row-b'
// A third row. With only two rows every predicate can return just [A], [B],
// [A,B] or [] — so an `eq` that over-matches a near-miss value is undetectable,
// and ordering can never carry a tie. Row `i` takes `samples[min(i, len-1)]`
// per domain (the scheme `v3-matrix/matrix-live-pg.test.ts` already uses), so
// domains with a third distinct sample get a near-miss row, and domains with
// only two (date, timestamp, boolean) get a deliberate ORDER BY tie with ROW_B.
const ROW_C = 'row-c'
const ROWS = [ROW_A, ROW_B, ROW_C] as const

const matrixEntries = typedEntries(V3_MATRIX)
const matrixColumns = Object.fromEntries(
  matrixEntries.map(([eqlType, spec]) => [
    slug(eqlType),
    makeEqlV3Column(spec.builder(slug(eqlType))),
  ]),
)

const matrixTable = pgTable(TABLE_NAME, {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  rowKey: text('row_key').notNull(),
  testRunId: text('test_run_id').notNull(),
  nullableTextEq: makeEqlV3Column(
    V3_MATRIX['public.text_eq'].builder('nullable_text_eq'),
  ),
  ...matrixColumns,
})

const accountsTable = pgTable(ACCOUNT_TABLE_NAME, {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  rowKey: text('row_key').notNull(),
  label: text('label').notNull(),
  testRunId: text('test_run_id').notNull(),
})

// A statically-typed encrypted table (via the drizzle `types` namespace) with
// concrete bigint columns. Unlike the dynamic matrix table, its column set is
// known at compile time, so it exercises A3 end-to-end with ZERO casts: the
// insert takes envelope rows and the select yields `Encrypted` values ready for
// decrypt.
const BIGINT_TABLE_NAME = 'protect_ci_v3_drizzle_bigint'
const bigintTable = pgTable(BIGINT_TABLE_NAME, {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  rowKey: text('row_key').notNull(),
  testRunId: text('test_run_id').notNull(),
  balance: v3drizzle.BigintOrd('balance'),
  ledger: v3drizzle.BigintEq('ledger'),
})

// Full i64 bounds — proves protect-ffi 0.28 round-trips a JS bigint beyond
// Number.MAX_SAFE_INTEGER losslessly through the encrypted column.
const BIGINT_BALANCE = 9223372036854775807n
const BIGINT_LEDGER = -9223372036854775808n
// A second row the filters must exclude: a negative balance (so `gt(0n)` has
// something to reject) and a small positive ledger.
const BIGINT_B_BALANCE = -5n
const BIGINT_B_LEDGER = 100n

const schema = extractEncryptionSchemaV3(matrixTable)
const bigintSchema = extractEncryptionSchemaV3(bigintTable)

type PlainValue = string | number | bigint | boolean | Date
type RowKey = (typeof ROWS)[number]
type MatrixPlainRow = Record<string, PlainValue | null | string>
type SelectRow = { rowKey: string }
type Db = ReturnType<typeof drizzle>
type Client = Awaited<ReturnType<typeof EncryptionV3>>
type Ops = ReturnType<typeof createEncryptionOperatorsV3>
type ComparisonOperator = 'gt' | 'gte' | 'lt' | 'lte'

let client: Client
let ops: Ops
let db: Db

const equalityDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.unique || spec.indexes.ore,
)
const orderDomains = matrixEntries.filter(([, spec]) => spec.indexes.ore)
const matchDomains = matrixEntries.filter(([, spec]) => spec.indexes.match)
const noEqualityDomains = matrixEntries.filter(
  ([, spec]) => !spec.indexes.unique && !spec.indexes.ore,
)
const noOrderDomains = matrixEntries.filter(([, spec]) => !spec.indexes.ore)
const noMatchDomains = matrixEntries.filter(([, spec]) => !spec.indexes.match)
const comparisonOperators: Array<
  [ComparisonOperator, (cmp: number) => boolean]
> = [
  ['gt', (cmp) => cmp > 0],
  ['gte', (cmp) => cmp >= 0],
  ['lt', (cmp) => cmp < 0],
  ['lte', (cmp) => cmp <= 0],
]
const comparisonDomains = orderDomains.flatMap(([eqlType, spec]) =>
  comparisonOperators.map(
    ([operator, predicate]) => [eqlType, spec, operator, predicate] as const,
  ),
)

const matrixColumn = (eqlType: EqlV3TypeName): SQLWrapper =>
  (matrixTable as unknown as Record<string, SQLWrapper>)[slug(eqlType)]

const scoped = (cond: SQL | undefined): SQL | undefined =>
  cond ? and(drizzleEq(matrixTable.testRunId, RUN), cond) : cond

const plainValue = (spec: DomainSpec, rowKey: RowKey): PlainValue =>
  spec.samples[Math.min(ROWS.indexOf(rowKey), spec.samples.length - 1)]

function comparePlain(left: PlainValue, right: PlainValue): number {
  if (left instanceof Date && right instanceof Date) {
    return left.getTime() - right.getTime()
  }
  if (typeof left === 'number' && typeof right === 'number') {
    return left - right
  }
  // bigint order domains (`bigint_ord`/`bigint_ord_ore`) carry i64 samples
  // beyond Number.MAX_SAFE_INTEGER, so they must be compared as bigints — the
  // subtraction is narrowed to -1/0/1 because callers expect a `number`.
  if (typeof left === 'bigint' && typeof right === 'bigint') {
    return left < right ? -1 : left > right ? 1 : 0
  }
  if (typeof left === 'string' && typeof right === 'string') {
    // eql_v3 text ordering (ORE) is BYTEWISE, not locale-collated: the oracle
    // must model codepoint order, not `localeCompare` (which folds case,
    // reorders punctuation vs letters, and is locale-dependent). Text samples
    // must stay ASCII/unambiguous so UTF-16 code-unit order == the byte order
    // the DB actually sorts by.
    return left < right ? -1 : left > right ? 1 : 0
  }
  throw new Error(
    `Unsupported ordered values: ${String(left)}, ${String(right)}`,
  )
}

function expectedKeysFor(
  spec: DomainSpec,
  predicate: (value: PlainValue) => boolean,
): RowKey[] {
  return ROWS.filter((rowKey) => predicate(plainValue(spec, rowKey)))
}

/**
 * Oracle for the encrypted ORDER BY. Domains with only two samples give ROW_B
 * and ROW_C equal values, so the comparison alone does not determine the row
 * order — ties break on `rowKey` ascending, which the query mirrors with a
 * secondary `ORDER BY row_key`. Without that both sides would be arbitrary and
 * the test would flake rather than prove ordering.
 */
function sortedKeysFor(spec: DomainSpec, direction: 'asc' | 'desc'): RowKey[] {
  return [...ROWS].sort((left, right) => {
    const cmp = comparePlain(plainValue(spec, left), plainValue(spec, right))
    if (cmp !== 0) return direction === 'asc' ? cmp : -cmp
    return left < right ? -1 : left > right ? 1 : 0
  })
}

async function selectRowKeys(condition: SQL | undefined): Promise<string[]> {
  if (!condition) throw new Error('Expected query condition')
  const rows = (await db
    .select({ rowKey: matrixTable.rowKey })
    .from(matrixTable)
    .where(scoped(condition))
    .orderBy(drizzleAsc(matrixTable.rowKey))) as SelectRow[]
  return rows.map((row) => row.rowKey)
}

function unwrap<T>(result: { data?: T; failure?: { message: string } }): T {
  if (result.failure) throw new Error(result.failure.message)
  return result.data as T
}

function encryptedInsertRows(): MatrixPlainRow[] {
  return ROWS.map((rowKey) => {
    const row: MatrixPlainRow = {
      rowKey,
      testRunId: RUN,
      nullableTextEq: rowKey === ROW_A ? null : `nullable-${rowKey}`,
    }
    for (const [eqlType, spec] of matrixEntries) {
      row[slug(eqlType)] = plainValue(spec, rowKey)
    }
    return row
  })
}

beforeAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return
  await installEqlV3IfNeeded(sqlClient)
  client = await EncryptionV3({ schemas: [schema, bigintSchema] })
  ops = createEncryptionOperatorsV3(client)
  db = drizzle({ client: sqlClient })

  const columnDefs = matrixEntries
    .map(([eqlType]) => `"${slug(eqlType)}" ${eqlType} NOT NULL`)
    .join(',\n      ')

  await sqlClient.unsafe(`
    CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      test_run_id TEXT NOT NULL,
      nullable_text_eq public.text_eq,
      ${columnDefs}
    )
  `)
  await sqlClient.unsafe(`
    CREATE TABLE IF NOT EXISTS ${ACCOUNT_TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      label TEXT NOT NULL,
      test_run_id TEXT NOT NULL
    )
  `)
  await sqlClient.unsafe(`
    CREATE TABLE IF NOT EXISTS ${BIGINT_TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      test_run_id TEXT NOT NULL,
      balance public.bigint_ord NOT NULL,
      ledger public.bigint_eq NOT NULL
    )
  `)

  const encryptedRows = unwrap(
    await client.bulkEncryptModels(encryptedInsertRows(), schema),
  )
  await db.insert(matrixTable).values(encryptedRows)
  await db.insert(accountsTable).values([
    { rowKey: ROW_A, label: 'primary', testRunId: RUN },
    { rowKey: ROW_B, label: 'secondary', testRunId: RUN },
  ])

  // A3 end-to-end, cast-free: encrypt a native bigint model, insert the
  // resulting envelope rows (typed against the column's `Encrypted` data slot),
  // no `as never` anywhere.
  //
  // ROW_B exists so the filter proofs below have a row they must EXCLUDE. On a
  // one-row table `gt(balance, 0n)` returning every row is indistinguishable
  // from it returning the right row.
  const bigintRows = unwrap(
    await client.bulkEncryptModels(
      [
        {
          rowKey: ROW_A,
          testRunId: RUN,
          balance: BIGINT_BALANCE,
          ledger: BIGINT_LEDGER,
        },
        {
          rowKey: ROW_B,
          testRunId: RUN,
          balance: BIGINT_B_BALANCE,
          ledger: BIGINT_B_LEDGER,
        },
      ],
      bigintSchema,
    ),
  )
  await db.insert(bigintTable).values(bigintRows)
}, 120000)

afterAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return
  await sqlClient`DELETE FROM ${sqlClient(TABLE_NAME)} WHERE test_run_id = ${RUN}`
  await sqlClient`DELETE FROM ${sqlClient(ACCOUNT_TABLE_NAME)} WHERE test_run_id = ${RUN}`
  await sqlClient`DELETE FROM ${sqlClient(BIGINT_TABLE_NAME)} WHERE test_run_id = ${RUN}`
  await sqlClient.end()
}, 30000)

describeLivePg('v3 drizzle operators (live pg matrix)', () => {
  it.each(equalityDomains)(
    '%s eq selects the exact row',
    async (eqlType, spec) => {
      const bound = plainValue(spec, ROW_A)
      const rows = await selectRowKeys(
        await ops.eq(matrixColumn(eqlType), bound),
      )
      // Oracle, not `[ROW_A]`: ROW_C carries a near-miss value for domains with
      // a third sample, so an `eq` that over-matches now shows up here.
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => comparePlain(value, bound) === 0),
      )
    },
    30000,
  )

  it.each(equalityDomains)(
    '%s ne selects the complement rows',
    async (eqlType, spec) => {
      const bound = plainValue(spec, ROW_A)
      const rows = await selectRowKeys(
        await ops.ne(matrixColumn(eqlType), bound),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => comparePlain(value, bound) !== 0),
      )
    },
    30000,
  )

  it.each(equalityDomains)(
    '%s inArray selects all listed rows',
    async (eqlType, spec) => {
      const listed = [plainValue(spec, ROW_A), plainValue(spec, ROW_B)]
      const rows = await selectRowKeys(
        await ops.inArray(matrixColumn(eqlType), listed),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) =>
          listed.some((entry) => comparePlain(value, entry) === 0),
        ),
      )
    },
    30000,
  )

  it.each(equalityDomains)(
    '%s notInArray excludes listed rows',
    async (eqlType, spec) => {
      const bound = plainValue(spec, ROW_A)
      const rows = await selectRowKeys(
        await ops.notInArray(matrixColumn(eqlType), [bound]),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => comparePlain(value, bound) !== 0),
      )
    },
    30000,
  )

  it.each(comparisonDomains)(
    '%s %s selects rows by encrypted ordering',
    async (eqlType, spec, operator, predicate) => {
      const bound = plainValue(spec, ROW_A)
      const rows = await selectRowKeys(
        await ops[operator](matrixColumn(eqlType), bound),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => predicate(comparePlain(value, bound))),
      )
    },
    30000,
  )

  // The bounds span ROW_A and ROW_B. ROW_C carries a third sample that may sit
  // outside that span (most domains) or tie with ROW_B (date, timestamp), so
  // membership is computed rather than assumed — with only A and B seeded these
  // were `[ROW_A, ROW_B]` and `[]`, which no longer holds.
  const spanBounds = (spec: DomainSpec): [PlainValue, PlainValue] => {
    const sorted = [plainValue(spec, ROW_A), plainValue(spec, ROW_B)].sort(
      comparePlain,
    )
    return [sorted[0], sorted[1]]
  }
  const withinSpan = (spec: DomainSpec) => (value: PlainValue) => {
    const [min, max] = spanBounds(spec)
    return comparePlain(value, min) >= 0 && comparePlain(value, max) <= 0
  }

  it.each(orderDomains)(
    '%s between selects the inclusive range',
    async (eqlType, spec) => {
      const [min, max] = spanBounds(spec)
      const rows = await selectRowKeys(
        await ops.between(matrixColumn(eqlType), min, max),
      )
      expect(rows).toEqual(expectedKeysFor(spec, withinSpan(spec)))
    },
    30000,
  )

  it.each(orderDomains)(
    '%s notBetween excludes the inclusive range',
    async (eqlType, spec) => {
      const [min, max] = spanBounds(spec)
      const rows = await selectRowKeys(
        await ops.notBetween(matrixColumn(eqlType), min, max),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => !withinSpan(spec)(value)),
      )
    },
    30000,
  )

  // The spanning cases above put ROW_A and ROW_B inside the range, so on most
  // domains only ROW_C proves exclusion. These narrow cases use a single-point
  // range at ROW_A's value to prove the operators EXCLUDE regardless of where
  // ROW_C falls: `between` must drop ROW_B, `notBetween` must keep it. Without
  // these, a `between` that matched everything (or a `notBetween` no-op) passes.
  it.each(orderDomains)(
    '%s between at a single point excludes the out-of-range row',
    async (eqlType, spec) => {
      const bound = plainValue(spec, ROW_A)
      const rows = await selectRowKeys(
        await ops.between(matrixColumn(eqlType), bound, bound),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => comparePlain(value, bound) === 0),
      )
    },
    30000,
  )

  it.each(orderDomains)(
    '%s notBetween at a single point keeps the out-of-range row',
    async (eqlType, spec) => {
      const bound = plainValue(spec, ROW_A)
      const rows = await selectRowKeys(
        await ops.notBetween(matrixColumn(eqlType), bound, bound),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => comparePlain(value, bound) !== 0),
      )
    },
    30000,
  )

  // `between` returns a two-function conjunction; Drizzle's passthrough `not`
  // prepends a bare `not` with no parentheses of its own. Postgres binds NOT
  // tighter than AND, so an unparenthesised range would run as
  // `(NOT gte(col, bound)) AND lte(col, bound)` — i.e. `col < bound` — instead
  // of the range's complement, `col != bound`.
  //
  // The bound MUST be the SMALLER of the two seeded values. Anchored at the
  // larger one, `col < bound` and `col != bound` both select the other row and
  // the buggy SQL passes; anchored at the smaller, the buggy SQL selects
  // nothing while the correct SQL selects the larger row. Several domains seed
  // ROW_A with their maximum sample (`integer_ord` is `[0, -42]`), so keying
  // off ROW_A directly would make this test vacuous for them.
  it.each(orderDomains)(
    '%s not(between(...)) negates the whole range',
    async (eqlType, spec) => {
      const bound = [plainValue(spec, ROW_A), plainValue(spec, ROW_B)].sort(
        comparePlain,
      )[0]
      const rows = await selectRowKeys(
        ops.not(await ops.between(matrixColumn(eqlType), bound, bound)),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) => comparePlain(value, bound) !== 0),
      )
      // Guards the guard: the expectation must be non-empty, or the buggy
      // `col < bound` (which returns nothing) would satisfy it too.
      expect(rows.length).toBeGreaterThan(0)
    },
    30000,
  )

  // The secondary `ORDER BY row_key` mirrors the oracle's tie-break. Domains
  // with only two samples (date, timestamp) give ROW_B and ROW_C equal values,
  // so without it the tied pair's order is arbitrary in Postgres.
  it.each(orderDomains)(
    '%s asc orders by encrypted order term',
    async (eqlType, spec) => {
      const rows = (await db
        .select({ rowKey: matrixTable.rowKey })
        .from(matrixTable)
        .where(drizzleEq(matrixTable.testRunId, RUN))
        .orderBy(
          ops.asc(matrixColumn(eqlType)),
          drizzleAsc(matrixTable.rowKey),
        )) as SelectRow[]
      expect(rows.map((row) => row.rowKey)).toEqual(sortedKeysFor(spec, 'asc'))
    },
    30000,
  )

  it.each(orderDomains)(
    '%s desc orders by encrypted order term',
    async (eqlType, spec) => {
      const rows = (await db
        .select({ rowKey: matrixTable.rowKey })
        .from(matrixTable)
        .where(drizzleEq(matrixTable.testRunId, RUN))
        .orderBy(
          ops.desc(matrixColumn(eqlType)),
          drizzleAsc(matrixTable.rowKey),
        )) as SelectRow[]
      expect(rows.map((row) => row.rowKey)).toEqual(sortedKeysFor(spec, 'desc'))
    },
    30000,
  )

  // Needles are driven through the same substring oracle, so each domain gets
  // the rows it should. `'ada'` is exactly `token_length`; `'lovelace'` and
  // `'grace'` are longer (the suite previously had no `contains` proof above
  // the token length at all); `'qqqzzz'` is present in no row, so a `contains`
  // that matched everything would fail here rather than pass silently.
  it.each(
    matchDomains.flatMap(([eqlType, spec]) =>
      ['ada', 'lovelace', 'grace', 'qqqzzz'].map(
        (needle) => [eqlType, spec, needle] as const,
      ),
    ),
  )(
    '%s contains %s matches exactly the rows holding it',
    async (eqlType, spec, needle) => {
      const rows = await selectRowKeys(
        await ops.contains(matrixColumn(eqlType), needle),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) =>
          String(value).toLowerCase().includes(needle),
        ),
      )
    },
    30000,
  )

  // A needle below the tokenizer's `token_length` builds an EMPTY bloom filter,
  // and `stored_bf @> '{}'` holds for every row — so before the SDK guard this
  // silently returned the whole table.
  //
  // `'👍👍'` is the regression case: 4 UTF-16 code units but only 2 codepoints,
  // so a `needle.length` floor waved it through and it matched every row. The
  // tokenizer counts codepoints. `''` tokenizes to nothing under any tokenizer.
  it.each(
    matchDomains.flatMap(([eqlType]) =>
      ['ad', '👍👍', ''].map((needle) => [eqlType, needle] as const),
    ),
  )(
    '%s contains rejects the unanswerable needle %j before encrypting',
    async (eqlType, needle) => {
      const attempt = ops.contains(matrixColumn(eqlType), needle)
      await expect(attempt).rejects.toBeInstanceOf(EncryptionOperatorError)
      // Assert the GUARD rejected it, not the encryption layer.
      // `operandFailure` also throws `EncryptionOperatorError`, so matching only
      // the class would let an encryption error stand in for the guard and the
      // test would pass for the wrong reason.
      await expect(attempt).rejects.toThrow(/free-text search needs/)
    },
    30000,
  )

  // The complement: a needle that DOES reach the floor in codepoints must be
  // ANSWERED, not over-rejected — otherwise the fix for the astral fail-open
  // would just over-correct into rejecting usable needles.
  //
  // Restricted to match-ONLY columns: a column that also carries an `ore` index
  // (`text_search`) cannot encrypt a non-ASCII operand at all — the ORE term
  // raises "Can only order strings that are pure ASCII" — so a non-ASCII needle
  // there fails inside encryption, long after the guard has passed it. That
  // constraint is pinned by its own test below rather than silently conflated
  // with the codepoint floor.
  //
  // Escapes, not literals: the precomposed NFC form of `ee-with-accents` is only
  // 2 codepoints and IS rejected, so a bare literal would test the opposite case
  // depending on the file's on-disk normalisation.
  const NFD_EE = 'e\u0301e\u0301' // 4 codepoints, 2 grapheme clusters
  const matchOnlyDomains = matchDomains.filter(([, spec]) => !spec.indexes.ore)

  it.each(
    matchOnlyDomains.flatMap(([eqlType]) =>
      ['\u{1F44D}\u{1F44D}\u{1F44D}', NFD_EE].map(
        (needle) => [eqlType, needle] as const,
      ),
    ),
  )(
    '%s contains answers the codepoint-sufficient needle %j with no match',
    async (eqlType, needle) => {
      const rows = await selectRowKeys(
        await ops.contains(matrixColumn(eqlType), needle),
      )
      expect(rows).toEqual([])
    },
    30000,
  )

  // An `ore`-bearing match column rejects a non-ASCII needle inside ENCRYPTION,
  // not in the needle guard. Pinned so the distinction stays visible: the guard
  // is about tokenization, this is about the ORE term's ASCII-only ordering.
  it.each(
    matchDomains.filter(([, spec]) => spec.indexes.ore),
  )('%s contains rejects a non-ASCII needle in the ORE term, not the guard', async (eqlType) => {
    const attempt = ops.contains(
      matrixColumn(eqlType),
      '\u{1F44D}\u{1F44D}\u{1F44D}',
    )
    await expect(attempt).rejects.toThrow(/pure ASCII/)
    await expect(attempt).rejects.not.toThrow(/free-text search needs/)
  }, 30000)

  it.each(
    noEqualityDomains,
  )('%s eq rejects unsupported equality', async (eqlType, spec) => {
    await expect(
      ops.eq(matrixColumn(eqlType), plainValue(spec, ROW_A)),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it.each(
    noOrderDomains,
  )('%s gt rejects unsupported ordering', async (eqlType, spec) => {
    await expect(
      ops.gt(matrixColumn(eqlType), plainValue(spec, ROW_A)),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it.each(noOrderDomains)('%s asc rejects unsupported ordering', (eqlType) => {
    expect(() => ops.asc(matrixColumn(eqlType))).toThrow(
      EncryptionOperatorError,
    )
  })

  it.each(
    noMatchDomains,
  )('%s contains rejects unsupported match', async (eqlType, spec) => {
    await expect(
      ops.contains(matrixColumn(eqlType), plainValue(spec, ROW_A)),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  // The two predicates must be satisfied by DISJOINT row sets, or `and` and
  // `or` return the same thing and the test cannot tell them apart. The old
  // pairing (`text_eq = 'ada@example.com'` AND `integer_ord < 0`) was true for
  // ROW_B alone under both operators, so swapping `and` for `or` still passed.
  //   text_eq = 'ada@example.com' -> ROW_B only
  //   integer_ord >= 0           -> ROW_A (0) and ROW_C (2147483647), not ROW_B (-42)
  const disjointPredicates = () =>
    [
      ops.eq(matrixColumn('public.text_eq'), 'ada@example.com'),
      ops.gte(matrixColumn('public.integer_ord'), 0),
    ] as const

  it('and requires both encrypted predicates, unlike or', async () => {
    const rows = await selectRowKeys(await ops.and(...disjointPredicates()))
    expect(rows).toEqual([])
  }, 30000)

  it('or requires either encrypted predicate, unlike and', async () => {
    const rows = await selectRowKeys(await ops.or(...disjointPredicates()))
    expect(rows).toEqual([ROW_A, ROW_B, ROW_C])
  }, 30000)

  it('or combines encrypted predicates', async () => {
    const rows = await selectRowKeys(
      await ops.or(
        ops.eq(matrixColumn('public.text_eq'), ''),
        ops.eq(matrixColumn('public.text_eq'), 'ada@example.com'),
      ),
    )
    expect(rows).toEqual([ROW_A, ROW_B])
  }, 30000)

  it('not negates an encrypted predicate', async () => {
    const rows = await selectRowKeys(
      ops.not(await ops.eq(matrixColumn('public.text_eq'), '')),
    )
    expect(rows).toEqual([ROW_B, ROW_C])
  }, 30000)

  it('isNull and isNotNull work on nullable encrypted columns', async () => {
    expect(await selectRowKeys(ops.isNull(matrixTable.nullableTextEq))).toEqual(
      [ROW_A],
    )
    expect(
      await selectRowKeys(ops.isNotNull(matrixTable.nullableTextEq)),
    ).toEqual([ROW_B, ROW_C])
  }, 30000)

  it('exists and notExists work with correlated subqueries', async () => {
    const primaryAccount = db
      .select({ id: accountsTable.id })
      .from(accountsTable)
      .where(
        and(
          drizzleEq(accountsTable.testRunId, RUN),
          drizzleEq(accountsTable.rowKey, matrixTable.rowKey),
          drizzleEq(accountsTable.label, 'primary'),
        ),
      )
    const missingAccount = db
      .select({ id: accountsTable.id })
      .from(accountsTable)
      .where(
        and(
          drizzleEq(accountsTable.testRunId, RUN),
          drizzleEq(accountsTable.rowKey, matrixTable.rowKey),
          drizzleEq(accountsTable.label, 'missing'),
        ),
      )

    expect(await selectRowKeys(ops.exists(primaryAccount))).toEqual([ROW_A])
    // ROW_C has no account row at all, so it too has no 'missing' account.
    expect(await selectRowKeys(ops.notExists(missingAccount))).toEqual([
      ROW_A,
      ROW_B,
      ROW_C,
    ])
  }, 30000)

  it('joins plain tables while filtering encrypted columns', async () => {
    const rows = (await db
      .select({ rowKey: matrixTable.rowKey })
      .from(matrixTable)
      .innerJoin(
        accountsTable,
        and(
          drizzleEq(accountsTable.testRunId, RUN),
          drizzleEq(accountsTable.rowKey, matrixTable.rowKey),
        ),
      )
      .where(
        scoped(await ops.eq(matrixColumn('public.text_eq'), 'ada@example.com')),
      )) as SelectRow[]
    expect(rows.map((row) => row.rowKey)).toEqual([ROW_B])
  }, 30000)

  it('paginates encrypted ordering results with limit and offset', async () => {
    const spec = V3_MATRIX['public.integer_ord']
    const rows = (await db
      .select({ rowKey: matrixTable.rowKey })
      .from(matrixTable)
      .where(drizzleEq(matrixTable.testRunId, RUN))
      .orderBy(ops.asc(matrixColumn('public.integer_ord')))
      .limit(1)
      .offset(1)) as SelectRow[]
    expect(rows.map((row) => row.rowKey)).toEqual(
      sortedKeysFor(spec, 'asc').slice(1, 2),
    )
  }, 30000)

  // A real `TypedEncryptionClient` exposes `bulkEncrypt`, so these lists are
  // encrypted in one FFI crossing and the returned terms must line up
  // index-for-index with the values. Five values also crosses the
  // MAX_IN_ARRAY_CONCURRENCY=4 boundary of the single-encrypt fallback that a
  // `bulkEncrypt`-less client would take. Either way the OR/AND of eq/ne terms
  // must be correct — a misaligned bulk response would silently select the
  // wrong rows here.
  it('inArray encrypts a >4-value list in one bulk crossing', async () => {
    const rows = await selectRowKeys(
      await ops.inArray(matrixColumn('public.text_eq'), [
        'ada@example.com',
        '',
        'nobody-1@example.com',
        'nobody-2@example.com',
        'nobody-3@example.com',
      ]),
    )
    // '' -> ROW_A, 'ada@example.com' -> ROW_B; the three "nobody" terms match
    // nothing, exercising the pool without changing the expected set. ROW_C
    // ('Ada Lovelace') is listed by neither and must be excluded.
    expect(rows).toEqual([ROW_A, ROW_B])
  }, 30000)

  it('notInArray encrypts a >4-value list in one bulk crossing', async () => {
    const rows = await selectRowKeys(
      await ops.notInArray(matrixColumn('public.text_eq'), [
        '',
        'nobody-1@example.com',
        'nobody-2@example.com',
        'nobody-3@example.com',
        'nobody-4@example.com',
      ]),
    )
    // Only '' is excluded (ROW_A); ROW_B ('ada@example.com') and ROW_C
    // ('Ada Lovelace') survive.
    expect(rows).toEqual([ROW_B, ROW_C])
  }, 30000)

  // A3 + bigint lock: a statically-typed bigint table round-trips a real i64
  // value through encrypt → insert → select → decrypt with no casts. The select
  // yields `Encrypted`-typed columns (the envelope), fed straight to decrypt.
  it('round-trips a native bigint through a statically-typed encrypted column', async () => {
    const encrypted = await db
      .select({ balance: bigintTable.balance, ledger: bigintTable.ledger })
      .from(bigintTable)
      .where(
        and(
          drizzleEq(bigintTable.testRunId, RUN),
          drizzleEq(bigintTable.rowKey, ROW_A),
        ),
      )
    expect(encrypted).toHaveLength(1)

    const decrypted = unwrap(
      await client.decryptModel(encrypted[0], bigintSchema),
    )
    expect(decrypted.balance).toBe(BIGINT_BALANCE)
    expect(decrypted.ledger).toBe(BIGINT_LEDGER)
  }, 30000)

  // Each assertion below names a row that must be EXCLUDED. Against the former
  // one-row table an operator matching everything passed all of these.
  const bigintRowKeys = async (condition: SQL): Promise<string[]> => {
    const rows = (await db
      .select({ rowKey: bigintTable.rowKey })
      .from(bigintTable)
      .where(and(drizzleEq(bigintTable.testRunId, RUN), condition))
      .orderBy(drizzleAsc(bigintTable.rowKey))) as SelectRow[]
    return rows.map((row) => row.rowKey)
  }

  it('filters a bigint column by encrypted equality, excluding the other row', async () => {
    expect(
      await bigintRowKeys(await ops.eq(bigintTable.ledger, BIGINT_LEDGER)),
    ).toEqual([ROW_A])
    expect(
      await bigintRowKeys(await ops.eq(bigintTable.ledger, BIGINT_B_LEDGER)),
    ).toEqual([ROW_B])
    // i64::MIN and 100n are both representable; a needle matching neither row
    // must return nothing rather than everything.
    expect(await bigintRowKeys(await ops.eq(bigintTable.ledger, 7n))).toEqual(
      [],
    )
  }, 30000)

  it('filters a bigint column by encrypted ordering across zero', async () => {
    // ROW_B's balance is -5n, so `> 0n` must reject it.
    expect(await bigintRowKeys(await ops.gt(bigintTable.balance, 0n))).toEqual([
      ROW_A,
    ])
    expect(await bigintRowKeys(await ops.lt(bigintTable.balance, 0n))).toEqual([
      ROW_B,
    ])
    // Range up to i64::MAX inclusive: ROW_A sits exactly on the upper bound.
    expect(
      await bigintRowKeys(
        await ops.between(bigintTable.balance, 0n, BIGINT_BALANCE),
      ),
    ).toEqual([ROW_A])
  }, 30000)
})
