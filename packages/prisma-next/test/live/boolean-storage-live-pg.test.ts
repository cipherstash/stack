/**
 * Live-PG boolean storage: `public.eql_v3_boolean` is STORAGE-ONLY
 * (no indexes, all query capabilities false). Values survive
 * INSERT/SELECT/decrypt through the real client, and every search
 * operator refuses the column with `EncryptionOperatorError` — there
 * is no searchable term to mint.
 */

import 'dotenv/config'
import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptedBoolean } from '../../src/execution/envelope-boolean'
import { EncryptionOperatorError } from '../../src/v3/query-term'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
} from '../v3/operator-lowering-v3.helpers'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import {
  BOOLEAN,
  createLiveTable,
  decryptCell,
  insertEncryptedRows,
  type LiveV3Client,
  liveConnection,
  liveV3Contract,
  selectCell,
  setupLiveV3,
} from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const TABLE = 'pn_v3_live_boolean'
const COLUMNS = { active: BOOLEAN } as const
const contract = liveV3Contract(TABLE, COLUMNS)

describeLivePg('v3 boolean storage against live Postgres', () => {
  let sql: postgres.Sql
  let live: LiveV3Client

  beforeAll(async () => {
    sql = liveConnection()
    await installEqlV3IfNeeded(sql)
    await createLiveTable(sql, TABLE, COLUMNS)
    live = await setupLiveV3(contract)
    await insertEncryptedRows(sql, live.middleware, TABLE, [
      {
        id: 'on',
        cells: {
          active: { codecId: BOOLEAN, value: EncryptedBoolean.from(true) },
        },
      },
      {
        id: 'off',
        cells: {
          active: { codecId: BOOLEAN, value: EncryptedBoolean.from(false) },
        },
      },
    ])
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  it('true and false survive INSERT/SELECT/decrypt', async () => {
    const on = await decryptCell(live.sdk, EncryptedBoolean, {
      cell: await selectCell(sql, TABLE, 'active', 'on'),
      table: TABLE,
      column: 'active',
    })
    const off = await decryptCell(live.sdk, EncryptedBoolean, {
      cell: await selectCell(sql, TABLE, 'active', 'off'),
      table: TABLE,
      column: 'active',
    })
    expect(on).toBe(true)
    expect(off).toBe(false)
  }, 60_000)

  it('every search operator throws EncryptionOperatorError on the storage-only domain', () => {
    const active = () => columnAccessorV3(TABLE, 'active', BOOLEAN)
    // The full v3 registry — there is no negated match to attempt
    // (`eqlNotMatch` deliberately does not exist).
    const attempts: ReadonlyArray<readonly [string, unknown[]]> = [
      ['eqlEq', [true]],
      ['eqlNeq', [true]],
      ['eqlIn', [[true, false]]],
      ['eqlNotIn', [[true]]],
      ['eqlGt', [false]],
      ['eqlGte', [false]],
      ['eqlLt', [true]],
      ['eqlLte', [true]],
      ['eqlBetween', [false, true]],
      ['eqlNotBetween', [false, true]],
      ['eqlMatch', ['tru']],
      ['eqlJsonContains', [{ a: 1 }]],
    ]
    for (const [method, args] of attempts) {
      expect(
        () => callOperator(getOperator(method), active(), ...args),
        `${method} must refuse eql_v3_boolean`,
      ).toThrow(EncryptionOperatorError)
    }
  })
})
