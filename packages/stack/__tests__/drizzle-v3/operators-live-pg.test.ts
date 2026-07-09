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

const slug = (eqlType: EqlV3TypeName): string => eqlType.replace(/^public\./, '')
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

const schema = extractEncryptionSchemaV3(matrixTable)
const bigintSchema = extractEncryptionSchemaV3(bigintTable)

type PlainValue = string | number | boolean | Date
type RowKey = typeof ROW_A | typeof ROW_B
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
  spec.samples[rowKey === ROW_A ? 0 : 1]

function comparePlain(left: PlainValue, right: PlainValue): number {
  if (left instanceof Date && right instanceof Date) {
    return left.getTime() - right.getTime()
  }
  if (typeof left === 'number' && typeof right === 'number') {
    return left - right
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
  return ([ROW_A, ROW_B] as const).filter((rowKey) =>
    predicate(plainValue(spec, rowKey)),
  )
}

function sortedKeysFor(spec: DomainSpec, direction: 'asc' | 'desc'): RowKey[] {
  return ([ROW_A, ROW_B] as const).sort((left, right) => {
    const cmp = comparePlain(plainValue(spec, left), plainValue(spec, right))
    return direction === 'asc' ? cmp : -cmp
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
  return ([ROW_A, ROW_B] as const).map((rowKey) => {
    const row: MatrixPlainRow = {
      rowKey,
      testRunId: RUN,
      nullableTextEq: rowKey === ROW_A ? null : 'nullable-present',
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
  const bigintRows = unwrap(
    await client.bulkEncryptModels(
      [{ rowKey: ROW_A, testRunId: RUN, balance: BIGINT_BALANCE, ledger: BIGINT_LEDGER }],
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
      const rows = await selectRowKeys(
        await ops.eq(matrixColumn(eqlType), plainValue(spec, ROW_A)),
      )
      expect(rows).toEqual([ROW_A])
    },
    30000,
  )

  it.each(equalityDomains)(
    '%s ne selects the complement row',
    async (eqlType, spec) => {
      const rows = await selectRowKeys(
        await ops.ne(matrixColumn(eqlType), plainValue(spec, ROW_A)),
      )
      expect(rows).toEqual([ROW_B])
    },
    30000,
  )

  it.each(equalityDomains)(
    '%s inArray selects all listed rows',
    async (eqlType, spec) => {
      const rows = await selectRowKeys(
        await ops.inArray(matrixColumn(eqlType), [
          plainValue(spec, ROW_A),
          plainValue(spec, ROW_B),
        ]),
      )
      expect(rows).toEqual([ROW_A, ROW_B])
    },
    30000,
  )

  it.each(equalityDomains)(
    '%s notInArray excludes listed rows',
    async (eqlType, spec) => {
      const rows = await selectRowKeys(
        await ops.notInArray(matrixColumn(eqlType), [plainValue(spec, ROW_A)]),
      )
      expect(rows).toEqual([ROW_B])
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

  it.each(orderDomains)(
    '%s between selects the inclusive range',
    async (eqlType, spec) => {
      const sortedValues = [
        plainValue(spec, ROW_A),
        plainValue(spec, ROW_B),
      ].sort(comparePlain)
      const rows = await selectRowKeys(
        await ops.between(
          matrixColumn(eqlType),
          sortedValues[0],
          sortedValues[1],
        ),
      )
      expect(rows).toEqual([ROW_A, ROW_B])
    },
    30000,
  )

  it.each(orderDomains)(
    '%s notBetween excludes the inclusive range',
    async (eqlType, spec) => {
      const sortedValues = [
        plainValue(spec, ROW_A),
        plainValue(spec, ROW_B),
      ].sort(comparePlain)
      const rows = await selectRowKeys(
        await ops.notBetween(
          matrixColumn(eqlType),
          sortedValues[0],
          sortedValues[1],
        ),
      )
      expect(rows).toEqual([])
    },
    30000,
  )

  // The spanning cases above only ever prove INCLUSION (both rows are inside
  // the range, so `between` -> [A,B] and `notBetween` -> []). These narrow
  // cases use a single-point range at ROW_A's value to prove the operators
  // also EXCLUDE: `between` must drop ROW_B, `notBetween` must keep it. Without
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

  it.each(orderDomains)(
    '%s asc orders by encrypted order term',
    async (eqlType, spec) => {
      const rows = (await db
        .select({ rowKey: matrixTable.rowKey })
        .from(matrixTable)
        .where(drizzleEq(matrixTable.testRunId, RUN))
        .orderBy(ops.asc(matrixColumn(eqlType)))) as SelectRow[]
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
        .orderBy(ops.desc(matrixColumn(eqlType)))) as SelectRow[]
      expect(rows.map((row) => row.rowKey)).toEqual(sortedKeysFor(spec, 'desc'))
    },
    30000,
  )

  it.each(matchDomains)(
    '%s contains matches plaintext terms',
    async (eqlType, spec) => {
      const rows = await selectRowKeys(
        await ops.contains(matrixColumn(eqlType), 'ada'),
      )
      expect(rows).toEqual(
        expectedKeysFor(spec, (value) =>
          String(value).toLowerCase().includes('ada'),
        ),
      )
    },
    30000,
  )

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

  it('and combines encrypted predicates', async () => {
    const rows = await selectRowKeys(
      await ops.and(
        ops.eq(matrixColumn('public.text_eq'), 'ada@example.com'),
        ops.lt(matrixColumn('public.integer_ord'), 0),
      ),
    )
    expect(rows).toEqual([ROW_B])
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
    expect(rows).toEqual([ROW_B])
  }, 30000)

  it('isNull and isNotNull work on nullable encrypted columns', async () => {
    expect(await selectRowKeys(ops.isNull(matrixTable.nullableTextEq))).toEqual(
      [ROW_A],
    )
    expect(
      await selectRowKeys(ops.isNotNull(matrixTable.nullableTextEq)),
    ).toEqual([ROW_B])
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
    expect(await selectRowKeys(ops.notExists(missingAccount))).toEqual([
      ROW_A,
      ROW_B,
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

  // The matrix inArray/notInArray cases above use 2-element lists, so the
  // MAX_IN_ARRAY_CONCURRENCY=4 worker pool (operators.ts) never actually
  // concurrently encrypts more terms than the serial path would. These cross
  // the pool boundary: 5 values (> 4) forces the pool to reuse workers, and
  // must still produce the correct OR/AND of eq/ne terms.
  it('inArray encrypts a >4-value list through the concurrency pool', async () => {
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
    // nothing, exercising the pool without changing the expected set.
    expect(rows).toEqual([ROW_A, ROW_B])
  }, 30000)

  it('notInArray encrypts a >4-value list through the concurrency pool', async () => {
    const rows = await selectRowKeys(
      await ops.notInArray(matrixColumn('public.text_eq'), [
        '',
        'nobody-1@example.com',
        'nobody-2@example.com',
        'nobody-3@example.com',
        'nobody-4@example.com',
      ]),
    )
    // Only '' is excluded (ROW_A); ROW_B ('ada@example.com') survives.
    expect(rows).toEqual([ROW_B])
  }, 30000)

  // A3 + bigint lock: a statically-typed bigint table round-trips a real i64
  // value through encrypt → insert → select → decrypt with no casts. The select
  // yields `Encrypted`-typed columns (the envelope), fed straight to decrypt.
  it('round-trips a native bigint through a statically-typed encrypted column', async () => {
    const encrypted = await db
      .select({ balance: bigintTable.balance, ledger: bigintTable.ledger })
      .from(bigintTable)
      .where(drizzleEq(bigintTable.testRunId, RUN))
    expect(encrypted).toHaveLength(1)

    const decrypted = unwrap(
      await client.decryptModel(encrypted[0], bigintSchema),
    )
    expect(decrypted.balance).toBe(BIGINT_BALANCE)
    expect(decrypted.ledger).toBe(BIGINT_LEDGER)
  }, 30000)

  it('filters a bigint column by encrypted equality and ordering', async () => {
    const byLedger = (await db
      .select({ rowKey: bigintTable.rowKey })
      .from(bigintTable)
      .where(
        and(
          drizzleEq(bigintTable.testRunId, RUN),
          await ops.eq(bigintTable.ledger, BIGINT_LEDGER),
        ),
      )) as SelectRow[]
    expect(byLedger.map((row) => row.rowKey)).toEqual([ROW_A])

    const byBalance = (await db
      .select({ rowKey: bigintTable.rowKey })
      .from(bigintTable)
      .where(
        and(
          drizzleEq(bigintTable.testRunId, RUN),
          await ops.gt(bigintTable.balance, 0n),
        ),
      )) as SelectRow[]
    expect(byBalance.map((row) => row.rowKey)).toEqual([ROW_A])
  }, 30000)
})
