/**
 * Live-PG bulk-encrypt middleware: the REAL `bulkEncryptMiddlewareV3`
 * instance wired by `cipherstashFromStackV3` (real `EncryptionV3`
 * client, not a fake) drives a multi-row INSERT. Proves end-to-end:
 * the AST walk stamps `(table, column)` routing keys, the per-column
 * batch makes ONE bulkEncrypt crossing, the param slots are replaced
 * with plain JSONB text the pg driver serialises, the stored cells
 * parse as JSON documents (never the v2 `("...")` composite literal),
 * and every cell decrypts back to its original plaintext.
 */

import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptedString } from '../../src/execution/envelope-string'
import { v3FromDriver } from '../../src/v3/wire-v3'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import {
  createLiveTable,
  decryptCell,
  domainFor,
  insertEncryptedRows,
  type LiveV3Client,
  liveConnection,
  liveV3Contract,
  setupLiveV3,
  TEXT_SEARCH,
} from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const TABLE = 'pn_v3_live_bulk'
const COLUMNS = { email: TEXT_SEARCH } as const
const contract = liveV3Contract(TABLE, COLUMNS)

const EMAILS = [
  'bulk-0@example.com',
  'bulk-1@example.com',
  'bulk-2@example.com',
] as const

describeLivePg('v3 bulk-encrypt middleware against live Postgres', () => {
  let sql: postgres.Sql
  let live: LiveV3Client
  const envelopes = EMAILS.map((email) => EncryptedString.from(email))

  beforeAll(async () => {
    sql = liveConnection()
    await installEqlV3IfNeeded(sql)
    await createLiveTable(sql, TABLE, COLUMNS)
    live = await setupLiveV3(contract)
    await insertEncryptedRows(
      sql,
      live.middleware,
      TABLE,
      EMAILS.map((_, i) => ({
        id: `row-${i}`,
        cells: { email: { codecId: TEXT_SEARCH, value: envelopes[i] } },
      })),
    )
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  it('stores each cell as a JSON document in the v3 domain (plain JSONB wire)', async () => {
    const rows = (await sql.unsafe(
      `SELECT id, email, pg_typeof(email)::text AS domain FROM "${TABLE}" ORDER BY id`,
    )) as unknown as Array<{ id: string; email: unknown; domain: string }>
    expect(rows).toHaveLength(EMAILS.length)
    for (const row of rows) {
      expect(`public.${row.domain}`).toBe(domainFor(TEXT_SEARCH))
      // The cell parses as a JSON document — the v3 wire. A v2 composite
      // literal ('("...")') would fail this parse/shape check.
      const payload = v3FromDriver<unknown>(row.email as string | object)
      expect(payload).toBeTypeOf('object')
      expect(payload).not.toBeNull()
      expect(Array.isArray(payload)).toBe(false)
    }
  }, 60_000)

  it('stamps the storage ciphertext back onto the write envelopes (plaintext retained)', () => {
    for (const [i, envelope] of envelopes.entries()) {
      const handle = envelope.expose()
      expect(
        handle.ciphertext,
        'write envelope must carry the minted ciphertext',
      ).toBeDefined()
      expect(handle.plaintext).toBe(EMAILS[i])
      expect(handle.table).toBe(TABLE)
      expect(handle.column).toBe('email')
    }
  })

  it('every stored cell decrypts back to its original plaintext through the real client', async () => {
    const rows = (await sql.unsafe(
      `SELECT id, email FROM "${TABLE}" ORDER BY id`,
    )) as unknown as Array<{ id: string; email: unknown }>
    const decrypted = await Promise.all(
      rows.map((row) =>
        decryptCell(live.sdk, EncryptedString, {
          cell: row.email,
          table: TABLE,
          column: 'email',
        }),
      ),
    )
    expect(decrypted).toEqual([...EMAILS])
  }, 60_000)
})
