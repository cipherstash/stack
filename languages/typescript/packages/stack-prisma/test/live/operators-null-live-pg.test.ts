/**
 * Live-PG null handling: NULL cells pass through the real middleware
 * untouched (no encrypt crossing is minted for them), store as SQL
 * NULL in the `public.eql_v3_*` domain column, read back as NULL, and
 * the operators reject null OPERANDS with the isNull() hint instead of
 * minting a nonsense query term.
 */

import 'dotenv/config'
import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptedString } from '../../src/execution/envelope-string'
import { v3FromDriver } from '../../src/v3/wire-v3'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
} from '../v3/operator-lowering-v3.helpers'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import {
  createLiveTable,
  INTEGER_ORD,
  insertEncryptedRows,
  type LiveV3Client,
  liveConnection,
  liveV3Contract,
  runLoweredSelect,
  selectCell,
  selectIdsWhere,
  setupLiveV3,
  TEXT_SEARCH,
} from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const TABLE = 'pn_v3_live_nulls'
const COLUMNS = { email: TEXT_SEARCH, score: INTEGER_ORD } as const
const contract = liveV3Contract(TABLE, COLUMNS)

describeLivePg('v3 null round-trips against live Postgres', () => {
  let sql: postgres.Sql
  let live: LiveV3Client

  beforeAll(async () => {
    sql = liveConnection()
    await installEqlV3IfNeeded(sql)
    await createLiveTable(sql, TABLE, COLUMNS)
    live = await setupLiveV3(contract)
    await insertEncryptedRows(sql, live.middleware, TABLE, [
      {
        id: 'nully',
        cells: {
          email: { codecId: TEXT_SEARCH, value: null },
          score: { codecId: INTEGER_ORD, value: null },
        },
      },
      {
        id: 'filled',
        cells: {
          email: {
            codecId: TEXT_SEARCH,
            value: EncryptedString.from('filled@example.com'),
          },
          score: { codecId: INTEGER_ORD, value: null },
        },
      },
    ])
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  it('NULL cells store as SQL NULL and read back as null through the v3 wire', async () => {
    const emailCell = await selectCell(sql, TABLE, 'email', 'nully')
    const scoreCell = await selectCell(sql, TABLE, 'score', 'nully')
    expect(emailCell).toBeNull()
    expect(scoreCell).toBeNull()
    // The wire decode preserves null — this is the cell value the codec
    // layer would surface for a NULL column.
    expect(v3FromDriver(emailCell as null)).toBeNull()
  }, 60_000)

  it('a NULL column does not shadow non-null rows for operator queries', async () => {
    const result = await runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsWhere(
        TABLE,
        callOperator(
          getOperator('eqlEq'),
          columnAccessorV3(TABLE, 'email', TEXT_SEARCH),
          'filled@example.com',
        ),
      ),
    )
    expect(result.ids).toEqual(['filled'])
  }, 60_000)

  it('operators reject a null operand with the isNull() hint', () => {
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'email', TEXT_SEARCH),
        null,
      ),
    ).toThrow(/isNull/)
    expect(() =>
      callOperator(
        getOperator('eqlGt'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD),
        null,
      ),
    ).toThrow(/isNull/)
  })
})
