/**
 * Live-PG v3 operator round-trips, one capability tier per describe:
 * encrypt → INSERT (real middleware) → operator SELECT (real lowered
 * `eql_v3.*` SQL, real `encryptQuery` terms) → assert the EXPECTED ROWS
 * are selected → decrypt the stored cells back to the original
 * plaintext. Includes the ruled-decision-2 JSON containment case
 * (`@>` with `eql_v3.query_jsonb`).
 */

import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptedDate } from '../../src/execution/envelope-date'
import { EncryptedJson } from '../../src/execution/envelope-json'
import { EncryptedString } from '../../src/execution/envelope-string'
import { EncryptedNumber } from '../../src/v3/envelope-number'
import { cipherstashV3Asc, cipherstashV3Desc } from '../../src/v3/operators-v3'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
} from '../v3/operator-lowering-v3.helpers'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import {
  createLiveTable,
  DATE_ORD,
  decryptCell,
  INTEGER_ORD,
  insertEncryptedRows,
  JSON_CODEC,
  type LiveV3Client,
  liveConnection,
  liveV3Contract,
  runLoweredSelect,
  selectCell,
  selectIdsOrderBy,
  selectIdsWhere,
  setupLiveV3,
  TEXT_EQ,
  TEXT_SEARCH,
  TIMESTAMP_ORD,
} from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const TABLE = 'pn_v3_live_operators'
const COLUMNS = {
  email: TEXT_SEARCH,
  nickname: TEXT_EQ,
  score: INTEGER_ORD,
  birthday: DATE_ORD,
  seen_at: TIMESTAMP_ORD,
  payload: JSON_CODEC,
} as const

const contract = liveV3Contract(TABLE, COLUMNS)

const SEED = [
  {
    id: 'ada',
    email: 'ada@example.com',
    nickname: 'ada',
    score: 10,
    birthday: new Date('1990-01-15T00:00:00Z'),
    seenAt: new Date('2024-01-01T10:00:00Z'),
    payload: { role: 'admin', tags: ['pioneer'] },
  },
  {
    id: 'grace',
    email: 'grace@example.com',
    nickname: 'grace',
    score: 25,
    birthday: new Date('1985-06-30T00:00:00Z'),
    seenAt: new Date('2024-06-15T12:30:00Z'),
    payload: { role: 'user', tags: ['compiler'] },
  },
  {
    id: 'zora',
    email: 'zora@example.org',
    nickname: 'zora',
    score: 40,
    birthday: new Date('2001-12-05T00:00:00Z'),
    seenAt: new Date('2025-02-20T08:45:00Z'),
    payload: { role: 'admin', level: 3 },
  },
] as const

describeLivePg('v3 operators against live Postgres', () => {
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
          email: {
            codecId: TEXT_SEARCH,
            value: EncryptedString.from(row.email),
          },
          nickname: {
            codecId: TEXT_EQ,
            value: EncryptedString.from(row.nickname),
          },
          score: {
            codecId: INTEGER_ORD,
            value: EncryptedNumber.from(row.score),
          },
          birthday: {
            codecId: DATE_ORD,
            value: EncryptedDate.from(row.birthday),
          },
          seen_at: {
            codecId: TIMESTAMP_ORD,
            value: EncryptedDate.from(row.seenAt),
          },
          payload: {
            codecId: JSON_CODEC,
            value: EncryptedJson.from(row.payload),
          },
        },
      })),
    )
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  const where = (predicate: ReturnType<typeof callOperator>) =>
    runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsWhere(TABLE, predicate),
    )

  it('cipherstashEq on a text_search column selects exactly the matching row', async () => {
    const result = await where(
      callOperator(
        getOperator('cipherstashEq'),
        columnAccessorV3(TABLE, 'email', TEXT_SEARCH),
        'grace@example.com',
      ),
    )
    expect(result.sql).toContain('eql_v3.eq')
    expect(result.sql).toContain('::eql_v3.query_text_search')
    expect(result.ids).toEqual(['grace'])
  }, 60_000)

  it('cipherstashEq / cipherstashNe / cipherstashInArray on a text_eq column', async () => {
    const nickname = () => columnAccessorV3(TABLE, 'nickname', TEXT_EQ)
    const eq = await where(
      callOperator(getOperator('cipherstashEq'), nickname(), 'ada'),
    )
    expect(eq.ids).toEqual(['ada'])

    const ne = await where(
      callOperator(getOperator('cipherstashNe'), nickname(), 'ada'),
    )
    expect(ne.ids.sort()).toEqual(['grace', 'zora'])

    const inArray = await where(
      callOperator(getOperator('cipherstashInArray'), nickname(), [
        'ada',
        'zora',
      ]),
    )
    expect(inArray.ids.sort()).toEqual(['ada', 'zora'])
  }, 60_000)

  it('cipherstashIlike lowers to eql_v3.contains and finds the token match', async () => {
    const result = await where(
      callOperator(
        getOperator('cipherstashIlike'),
        columnAccessorV3(TABLE, 'email', TEXT_SEARCH),
        'grace',
      ),
    )
    expect(result.sql).toContain('eql_v3.contains')
    expect(result.ids).toEqual(['grace'])
  }, 60_000)

  it('cipherstashGt / cipherstashLte / cipherstashBetween on integer_ord select the right rows', async () => {
    const score = () => columnAccessorV3(TABLE, 'score', INTEGER_ORD)
    const gt = await where(
      callOperator(getOperator('cipherstashGt'), score(), 25),
    )
    expect(gt.ids).toEqual(['zora'])

    const lte = await where(
      callOperator(getOperator('cipherstashLte'), score(), 25),
    )
    expect(lte.ids.sort()).toEqual(['ada', 'grace'])

    const between = await where(
      callOperator(getOperator('cipherstashBetween'), score(), 11, 40),
    )
    expect(between.ids.sort()).toEqual(['grace', 'zora'])
  }, 60_000)

  it('cipherstashGt on date_ord and cipherstashBetween on timestamp_ord', async () => {
    const bornAfter = await where(
      callOperator(
        getOperator('cipherstashGt'),
        columnAccessorV3(TABLE, 'birthday', DATE_ORD),
        new Date('1990-01-01T00:00:00Z'),
      ),
    )
    expect(bornAfter.ids.sort()).toEqual(['ada', 'zora'])

    const seenIn2024 = await where(
      callOperator(
        getOperator('cipherstashBetween'),
        columnAccessorV3(TABLE, 'seen_at', TIMESTAMP_ORD),
        new Date('2024-01-01T00:00:00Z'),
        new Date('2024-12-31T23:59:59Z'),
      ),
    )
    expect(seenIn2024.ids.sort()).toEqual(['ada', 'grace'])
  }, 60_000)

  it('cipherstashV3Asc / Desc order by the encrypted order term', async () => {
    const score = () => columnAccessorV3(TABLE, 'score', INTEGER_ORD)
    const asc = await runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsOrderBy(TABLE, [cipherstashV3Asc(score())]),
    )
    expect(asc.sql).toContain('eql_v3.ord_term')
    expect(asc.ids).toEqual(['ada', 'grace', 'zora'])

    const desc = await runLoweredSelect(
      sql,
      live.middleware,
      contract,
      selectIdsOrderBy(TABLE, [cipherstashV3Desc(score())]),
    )
    expect(desc.ids).toEqual(['zora', 'grace', 'ada'])
  }, 60_000)

  it('cipherstashJsonContains (@> with eql_v3.query_jsonb) selects by encrypted containment', async () => {
    const result = await where(
      callOperator(
        getOperator('cipherstashJsonContains'),
        columnAccessorV3(TABLE, 'payload', JSON_CODEC),
        { role: 'admin' },
      ),
    )
    expect(result.sql).toContain('OPERATOR(public.@>)')
    expect(result.sql).toContain('::eql_v3.query_jsonb')
    expect(result.ids.sort()).toEqual(['ada', 'zora'])

    const nested = await where(
      callOperator(
        getOperator('cipherstashJsonContains'),
        columnAccessorV3(TABLE, 'payload', JSON_CODEC),
        { tags: ['compiler'] },
      ),
    )
    expect(nested.ids).toEqual(['grace'])
  }, 60_000)

  it('every domain family decrypts back to the original plaintext', async () => {
    const grace = SEED[1]
    const email = await decryptCell(live.sdk, EncryptedString, {
      cell: await selectCell(sql, TABLE, 'email', grace.id),
      table: TABLE,
      column: 'email',
    })
    expect(email).toBe(grace.email)

    const score = await decryptCell(live.sdk, EncryptedNumber, {
      cell: await selectCell(sql, TABLE, 'score', grace.id),
      table: TABLE,
      column: 'score',
    })
    expect(score).toBe(grace.score)

    const birthday = await decryptCell(live.sdk, EncryptedDate, {
      cell: await selectCell(sql, TABLE, 'birthday', grace.id),
      table: TABLE,
      column: 'birthday',
    })
    expect(birthday.toISOString().slice(0, 10)).toBe('1985-06-30')

    const seenAt = await decryptCell(live.sdk, EncryptedDate, {
      cell: await selectCell(sql, TABLE, 'seen_at', grace.id),
      table: TABLE,
      column: 'seen_at',
    })
    expect(seenAt.getTime()).toBe(grace.seenAt.getTime())

    const payload = await decryptCell(live.sdk, EncryptedJson, {
      cell: await selectCell(sql, TABLE, 'payload', grace.id),
      table: TABLE,
      column: 'payload',
    })
    expect(payload).toEqual(grace.payload)
  }, 60_000)
})
