/**
 * The Drizzle v3 tests the family driver cannot express.
 *
 * Per-domain equality, ordering, ranges, containment and capability rejections
 * moved to `families.integration.test.ts`, where they are derived from the
 * catalog and shared with the Supabase adapter. What remains is everything that
 * is about SQL shape rather than about a domain:
 *
 *   - boolean combinators (`and`/`or`/`not`) over disjoint encrypted predicates
 *   - `exists` / `notExists` correlated subqueries
 *   - joins against plain tables while filtering encrypted columns
 *   - `limit`/`offset` pagination over an encrypted ordering
 *   - the free-text needle guards: a needle below `token_length` blooms to
 *     nothing and `stored_bf @> '{}'` holds for EVERY row, so before the guard a
 *     short needle silently returned the whole table
 *   - a statically-typed bigint round-trip
 *
 * EQL v3 is installed once per run by `globalSetup`, via the real
 * `stash eql install`. This suite throws rather than skips when unconfigured.
 */

import { EncryptionV3 } from '@cipherstash/stack/v3'
import {
  type DomainSpec,
  databaseUrl,
  type EqlV3TypeName,
  isCovered,
  plainValue as plainValueFor,
  eqlTypeSlug as slug,
  sortedKeysFor as sortedKeysForKit,
  typedEntries,
  unwrapResult,
  V3_MATRIX,
} from '@cipherstash/test-kit'
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
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { makeEqlV3Column } from '../src/column'
import {
  createEncryptionOperators,
  EncryptionOperatorError,
  extractEncryptionSchema,
  types as v3drizzle,
} from '../src/index.js'

const sqlClient = postgres(databaseUrl(), { prepare: false })

// Per-run table suffix so two runs sharing a database (a persistent/reused CI
// database, a developer's local DB, or re-enabled file parallelism) never
// operate on the same physical table — one run's `beforeAll` DROP would
// otherwise blow away a table another run is mid-query on. Mirrors the family
// suites' run-scoped naming (`rows.ts` `planTable`).
const RID = Math.random().toString(36).slice(2, 8)
const TABLE_NAME = `protect_ci_v3_drizzle_matrix_${RID}`
const ACCOUNT_TABLE_NAME = `protect_ci_v3_drizzle_matrix_accounts_${RID}`
const RUN = `run-${Date.now()}-${RID}`
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

// Covered domains only. The `_ord_ore` rows are `deferred`: their columns cannot
// hold data on managed Postgres — the domain CHECK calls `ore_domain_unavailable`
// and the seed INSERT raises — so a table built from every row can only ever run
// against a superuser database. Filtering here is what lets this suite run on
// both the plain-Postgres and Supabase variants.
const matrixEntries = typedEntries(V3_MATRIX).filter(([, spec]) =>
  isCovered(spec),
)
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
    V3_MATRIX['public.eql_v3_text_eq'].builder('nullable_text_eq'),
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
const BIGINT_TABLE_NAME = `protect_ci_v3_drizzle_bigint_${RID}`
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

const schema = extractEncryptionSchema(matrixTable)
const bigintSchema = extractEncryptionSchema(bigintTable)

type PlainValue = string | number | bigint | boolean | Date
type RowKey = (typeof ROWS)[number]
type MatrixPlainRow = Record<string, PlainValue | null | string>
type SelectRow = { rowKey: string }
type Db = ReturnType<typeof drizzle>
type Client = Awaited<ReturnType<typeof EncryptionV3>>
type Ops = ReturnType<typeof createEncryptionOperators>
type ComparisonOperator = 'gt' | 'gte' | 'lt' | 'lte'

let client: Client
let ops: Ops
let db: Db

const equalityDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.unique || spec.indexes.ore || spec.indexes.ope,
)
const orderDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.ore || spec.indexes.ope,
)
const matchDomains = matrixEntries.filter(([, spec]) => spec.indexes.match)
const noEqualityDomains = matrixEntries.filter(
  ([, spec]) => !spec.indexes.unique && !spec.indexes.ore && !spec.indexes.ope,
)
const noOrderDomains = matrixEntries.filter(
  ([, spec]) => !spec.indexes.ore && !spec.indexes.ope,
)
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

// The plaintext oracle (`plainValue`, `comparePlain`, `sortedKeysFor`) lives in
// `@cipherstash/test-kit`, so the bytewise-ordering rules have a single home.
// These wrappers just bind this suite's fixed `ROWS` set.
const plainValue = (spec: DomainSpec, rowKey: RowKey): PlainValue =>
  plainValueFor(spec, ROWS, rowKey)

const sortedKeysFor = (spec: DomainSpec, direction: 'asc' | 'desc'): string[] =>
  sortedKeysForKit(spec, ROWS, direction)

async function selectRowKeys(condition: SQL | undefined): Promise<string[]> {
  if (!condition) throw new Error('Expected query condition')
  const rows = (await db
    .select({ rowKey: matrixTable.rowKey })
    .from(matrixTable)
    .where(scoped(condition))
    .orderBy(drizzleAsc(matrixTable.rowKey))) as SelectRow[]
  return rows.map((row) => row.rowKey)
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
  client = await EncryptionV3({ schemas: [schema, bigintSchema] })
  ops = createEncryptionOperators(client)
  db = drizzle({ client: sqlClient })

  const columnDefs = matrixEntries
    .map(([eqlType]) => `"${slug(eqlType)}" ${eqlType} NOT NULL`)
    .join(',\n      ')

  // Table names are run-scoped (see RID), so DROP IF EXISTS is normally a no-op;
  // it stays as a belt-and-braces guard against an id collision. Recreating from
  // scratch each run also means a catalog change can never silently reuse a
  // stale schema — the bug that bit once when the `_ord_ore` domains were
  // filtered out of `matrixEntries` but a leftover fixed-name table kept its nine
  // ORE columns, making every INSERT raise `ore_domain_unavailable` on managed
  // Postgres (the domain CHECK RAISEs even for a NULL value).
  await sqlClient.unsafe(`
    DROP TABLE IF EXISTS ${TABLE_NAME}
  `)
  await sqlClient.unsafe(`
    CREATE TABLE ${TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      test_run_id TEXT NOT NULL,
      nullable_text_eq public.eql_v3_text_eq,
      ${columnDefs}
    )
  `)
  await sqlClient.unsafe(`
    DROP TABLE IF EXISTS ${ACCOUNT_TABLE_NAME}
  `)
  await sqlClient.unsafe(`
    CREATE TABLE ${ACCOUNT_TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      label TEXT NOT NULL,
      test_run_id TEXT NOT NULL
    )
  `)
  await sqlClient.unsafe(`
    DROP TABLE IF EXISTS ${BIGINT_TABLE_NAME}
  `)
  await sqlClient.unsafe(`
    CREATE TABLE ${BIGINT_TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      test_run_id TEXT NOT NULL,
      balance public.eql_v3_bigint_ord NOT NULL,
      ledger public.eql_v3_bigint_eq NOT NULL
    )
  `)

  const encryptedRows = unwrapResult(
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
  const bigintRows = unwrapResult(
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
  // Tables are run-scoped, so drop them outright rather than DELETE-ing rows —
  // no other run shares them, and this leaves nothing behind on a persistent DB.
  await sqlClient.unsafe(`DROP TABLE IF EXISTS ${TABLE_NAME}`)
  await sqlClient.unsafe(`DROP TABLE IF EXISTS ${ACCOUNT_TABLE_NAME}`)
  await sqlClient.unsafe(`DROP TABLE IF EXISTS ${BIGINT_TABLE_NAME}`)
  await sqlClient.end()
}, 30000)

describe('v3 drizzle — relational, needle guards, pagination', () => {
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
    '%s matches rejects the unanswerable needle %j before encrypting',
    async (eqlType, needle) => {
      const attempt = ops.matches(matrixColumn(eqlType), needle)
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
  const matchOnlyDomains = matchDomains.filter(
    ([, spec]) => !spec.indexes.ore && !spec.indexes.ope,
  )

  it.each(
    matchOnlyDomains.flatMap(([eqlType]) =>
      ['\u{1F44D}\u{1F44D}\u{1F44D}', NFD_EE].map(
        (needle) => [eqlType, needle] as const,
      ),
    ),
  )(
    '%s matches answers the codepoint-sufficient needle %j with no match',
    async (eqlType, needle) => {
      const rows = await selectRowKeys(
        await ops.matches(matrixColumn(eqlType), needle),
      )
      expect(rows).toEqual([])

      // The control. An over-rejecting guard would have thrown above, and a
      // fail-open `contains` would have returned every row — but a
      // constant-false `contains` also returns [], and nothing above catches
      // it. Prove the same column still answers a needle that IS present.
      const present = await selectRowKeys(
        await ops.matches(matrixColumn(eqlType), 'ada'),
      )
      expect(present.length).toBeGreaterThan(0)
    },
    30000,
  )

  // The non-ASCII ORE-needle test that used to live here drove
  // `matchDomains.filter(([, spec]) => spec.indexes.ore)`. Since the eql-3.0.0
  // OPE re-pin, NO match domain carries an `ore` index — `text_search` is
  // `unique + ope + match`, `text_match` is `match` — so that `it.each` had zero
  // cases and reported nothing. A vacuous test reads exactly like a passing one.
  //
  // Assert the state instead. If an ORE-flavoured match domain ever returns, this
  // fails and whoever adds it has to restore the needle test with it.
  it('no match domain carries an ORE index, so no ASCII-only needle rule applies', () => {
    const oreMatchDomains = matchDomains.filter(([, spec]) => spec.indexes.ore)

    expect(oreMatchDomains.map(([eqlType]) => eqlType)).toEqual([])
  })

  // The two predicates must be satisfied by DISJOINT row sets, or `and` and
  // `or` return the same thing and the test cannot tell them apart. The old
  // pairing (`text_eq = 'ada@example.com'` AND `integer_ord < 0`) was true for
  // ROW_B alone under both operators, so swapping `and` for `or` still passed.
  //   text_eq = 'ada@example.com' -> ROW_B only
  //   integer_ord >= 0           -> ROW_A (0) and ROW_C (2147483647), not ROW_B (-42)
  const disjointPredicates = () =>
    [
      ops.eq(matrixColumn('public.eql_v3_text_eq'), 'ada@example.com'),
      ops.gte(matrixColumn('public.eql_v3_integer_ord'), 0),
    ] as const

  // Two assertions, one block, deliberately. The disjoint pair proves `and` is
  // not `or`: swapping the operator turns [] into [A,B,C]. But [] is also what
  // a constant-false `and` returns, and `beforeAll` cannot catch that — it only
  // catches a failed seed. The intersecting pair is the control that can: it
  // must return its row, so it dies on a constant-false `and` and on an eq/lt
  // term that silently matches nothing. Keeping it in a sibling `it` would not
  // couple them, since vitest runs on past a failure and the sibling could go
  // red while this stayed green.
  //   text_eq = 'ada@example.com' -> ROW_B only
  //   integer_ord >= 0            -> ROW_A (0), ROW_C (2147483647), not ROW_B (-42)
  //   integer_ord < 0             -> ROW_B (-42) only
  it('and requires both encrypted predicates, unlike or', async () => {
    expect(await selectRowKeys(await ops.and(...disjointPredicates()))).toEqual(
      [],
    )

    const intersecting = await selectRowKeys(
      await ops.and(
        ops.eq(matrixColumn('public.eql_v3_text_eq'), 'ada@example.com'),
        ops.lt(matrixColumn('public.eql_v3_integer_ord'), 0),
      ),
    )
    expect(intersecting).toEqual([ROW_B])
  }, 30000)

  it('or requires either encrypted predicate, unlike and', async () => {
    const rows = await selectRowKeys(await ops.or(...disjointPredicates()))
    expect(rows).toEqual([ROW_A, ROW_B, ROW_C])
  }, 30000)

  it('or combines encrypted predicates', async () => {
    const rows = await selectRowKeys(
      await ops.or(
        ops.eq(matrixColumn('public.eql_v3_text_eq'), ''),
        ops.eq(matrixColumn('public.eql_v3_text_eq'), 'ada@example.com'),
      ),
    )
    expect(rows).toEqual([ROW_A, ROW_B])
  }, 30000)

  it('not negates an encrypted predicate', async () => {
    const rows = await selectRowKeys(
      ops.not(await ops.eq(matrixColumn('public.eql_v3_text_eq'), '')),
    )
    expect(rows).toEqual([ROW_B, ROW_C])
  }, 30000)

  it('not(between()) negates the whole range, not just the lower bound', async () => {
    // integer_ord: ROW_A=0, ROW_B=-42, ROW_C=2147483647. `not(between(0, 0))`
    // must return every row whose value != 0 → ROW_B and ROW_C.
    //
    // `between` emits a TWO-clause conjunction, and Drizzle's passthrough `not`
    // renders a bare `NOT <cond>`. Postgres binds NOT tighter than AND, so this
    // only works because `v3Dialect.range` already parenthesises `(gte AND lte)`.
    // Without those parens, `NOT gte(0) AND lte(0)` parses as
    // `value < 0 AND value <= 0` = `value < 0` = ROW_B alone, silently dropping
    // ROW_C. Asserting ROW_C is present is what discriminates the two — a
    // single-bound complement would satisfy the buggy form too.
    const rows = await selectRowKeys(
      ops.not(
        await ops.between(matrixColumn('public.eql_v3_integer_ord'), 0, 0),
      ),
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
        scoped(
          await ops.eq(
            matrixColumn('public.eql_v3_text_eq'),
            'ada@example.com',
          ),
        ),
      )) as SelectRow[]
    expect(rows.map((row) => row.rowKey)).toEqual([ROW_B])
  }, 30000)

  it('paginates encrypted ordering results with limit and offset', async () => {
    const spec = V3_MATRIX['public.eql_v3_integer_ord']
    const rows = (await db
      .select({ rowKey: matrixTable.rowKey })
      .from(matrixTable)
      .where(drizzleEq(matrixTable.testRunId, RUN))
      .orderBy(ops.asc(matrixColumn('public.eql_v3_integer_ord')))
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
      await ops.inArray(matrixColumn('public.eql_v3_text_eq'), [
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
      await ops.notInArray(matrixColumn('public.eql_v3_text_eq'), [
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

    const decrypted = unwrapResult(
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
