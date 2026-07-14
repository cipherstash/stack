/**
 * Live-PG bigint family: `public.eql_v3_bigint` (storage-only),
 * `eql_v3_bigint_eq` (equality), `eql_v3_bigint_ord` (equality +
 * order/range). Proves a JS `bigint` plaintext survives losslessly —
 * including a value ABOVE `Number.MAX_SAFE_INTEGER`, which a
 * number-typed pipeline would corrupt — and that the encrypted
 * ordering terms order the real domain correctly.
 */

import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptedBigInt } from '../../src/execution/envelope-bigint'
import { cipherstashV3Asc } from '../../src/v3/operators-v3'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
} from '../v3/operator-lowering-v3.helpers'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import {
  BIGINT_EQ,
  BIGINT_ORD,
  BIGINT_STORAGE,
  createLiveTable,
  decryptCell,
  insertEncryptedRows,
  type LiveV3Client,
  liveConnection,
  liveV3Contract,
  runLoweredSelect,
  selectCell,
  selectIdsOrderBy,
  selectIdsWhere,
  setupLiveV3,
} from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const TABLE = 'pn_v3_live_bigint'
const COLUMNS = {
  balance: BIGINT_STORAGE,
  balance_eq: BIGINT_EQ,
  balance_ord: BIGINT_ORD,
} as const
const contract = liveV3Contract(TABLE, COLUMNS)

// 2^53 + 1: NOT representable as a JS number. Losslessness here proves
// the pipeline is bigint end-to-end (protect-ffi's eqlVersion-3 int8).
const UNSAFE_BIG = 9_007_199_254_740_993n

const SEED = [
  { id: 'small', value: 42n },
  { id: 'negative', value: -7n },
  { id: 'huge', value: UNSAFE_BIG },
] as const

describeLivePg('v3 bigint domains against live Postgres', () => {
  let sql: postgres.Sql
  let live: LiveV3Client

  beforeAll(async () => {
    sql = liveConnection()
    await installEqlV3IfNeeded(sql)
    await createLiveTable(sql, TABLE, COLUMNS)
    live = await setupLiveV3(contract)
    await insertEncryptedRows(
      sql,
      live.middleware,
      TABLE,
      SEED.map((row) => ({
        id: row.id,
        cells: {
          balance: {
            codecId: BIGINT_STORAGE,
            value: EncryptedBigInt.from(row.value),
          },
          balance_eq: {
            codecId: BIGINT_EQ,
            value: EncryptedBigInt.from(row.value),
          },
          balance_ord: {
            codecId: BIGINT_ORD,
            value: EncryptedBigInt.from(row.value),
          },
        },
      })),
    )
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  it('decrypts to a JS bigint, losslessly, beyond Number.MAX_SAFE_INTEGER', async () => {
    for (const column of ['balance', 'balance_eq', 'balance_ord'] as const) {
      const decrypted = await decryptCell(live.sdk, EncryptedBigInt, {
        cell: await selectCell(sql, TABLE, column, 'huge'),
        table: TABLE,
        column,
      })
      expect(typeof decrypted, `${column} must decrypt to bigint`).toBe(
        'bigint',
      )
      expect(decrypted).toBe(UNSAFE_BIG)
    }

    const negative = await decryptCell(live.sdk, EncryptedBigInt, {
      cell: await selectCell(sql, TABLE, 'balance', 'negative'),
      table: TABLE,
      column: 'balance',
    })
    expect(negative).toBe(-7n)
  }, 60_000)

  it('cipherstashEq on bigint_eq selects exactly the matching row', async () => {
    const result = await runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsWhere(
        TABLE,
        callOperator(
          getOperator('cipherstashEq'),
          columnAccessorV3(TABLE, 'balance_eq', BIGINT_EQ),
          UNSAFE_BIG,
        ),
      ),
    )
    expect(result.sql).toContain('::eql_v3.query_bigint_eq')
    expect(result.ids).toEqual(['huge'])
  }, 60_000)

  it('range predicates on bigint_ord respect numeric order across the huge value', async () => {
    const ord = () => columnAccessorV3(TABLE, 'balance_ord', BIGINT_ORD)
    const gt = await runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsWhere(
        TABLE,
        callOperator(getOperator('cipherstashGt'), ord(), 42n),
      ),
    )
    expect(gt.ids).toEqual(['huge'])

    const between = await runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsWhere(
        TABLE,
        callOperator(getOperator('cipherstashBetween'), ord(), -100n, 100n),
      ),
    )
    expect(between.ids.sort()).toEqual(['negative', 'small'])
  }, 60_000)

  it('orders by the encrypted order term in numeric order', async () => {
    const asc = await runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsOrderBy(TABLE, [
        cipherstashV3Asc(columnAccessorV3(TABLE, 'balance_ord', BIGINT_ORD)),
      ]),
    )
    expect(asc.sql).toContain('eql_v3.ord_term')
    expect(asc.ids).toEqual(['negative', 'small', 'huge'])
  }, 60_000)

  it('the storage-only bigint domain refuses search operators', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashEq'),
        columnAccessorV3(TABLE, 'balance', BIGINT_STORAGE),
        42n,
      ),
    ).toThrow(/equality/)
  })
})
