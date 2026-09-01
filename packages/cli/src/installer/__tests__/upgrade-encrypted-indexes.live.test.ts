/**
 * Credentialed upgrade coverage: a released EQL bundle owns the original
 * database objects, protect-ffi writes genuine ciphertext, and the public CLI
 * installer replaces that bundle without breaking the encrypted indexes.
 */

import { readInstallSql as readBaselineInstallSql } from '@cipherstash/eql-upgrade-baseline/sql'
import {
  decryptBulk,
  type EncryptConfig,
  type EncryptedPayload,
  encryptBulk,
  encryptQuery,
  newClient,
} from '@cipherstash/protect-ffi'
import { config as loadEnv } from 'dotenv'
import pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EQLInstaller } from '../index.js'

loadEnv({
  path: new URL('../../../../stack/.env', import.meta.url),
  quiet: true,
})

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const hasCredentials = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
].every((name) => process.env[name])
const describeLive = DATABASE_URL && hasCredentials ? describe : describe.skip

const BASELINE_VERSION = '3.0.2'
const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    eql_upgrade_records: {
      email: { cast_as: 'text', indexes: { unique: {} } },
      score: { cast_as: 'int', indexes: { ore: {} } },
    },
  },
}

describeLive('EQLInstaller upgrade — genuine encrypted indexes', () => {
  const client = new pg.Client({ connectionString: DATABASE_URL })
  let protectClient: Awaited<ReturnType<typeof newClient>>

  beforeAll(async () => {
    await client.connect()
    await client.query('DROP TABLE IF EXISTS eql_upgrade_records')
    await client.query(readBaselineInstallSql())
    expect(
      (
        await client.query<{ version: string }>(
          'SELECT eql_v3.version() AS version',
        )
      ).rows[0].version,
    ).toBe(BASELINE_VERSION)

    protectClient = await newClient({ encryptConfig, eqlVersion: 3 })
    const rows = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: 'alice@example.com',
          column: 'email',
          table: 'eql_upgrade_records',
        },
        { plaintext: 10, column: 'score', table: 'eql_upgrade_records' },
        {
          plaintext: 'bob@example.com',
          column: 'email',
          table: 'eql_upgrade_records',
        },
        { plaintext: 20, column: 'score', table: 'eql_upgrade_records' },
      ],
    })
    await client.query(`
      CREATE TABLE eql_upgrade_records (
        id integer PRIMARY KEY,
        email public.eql_v3_text_eq NOT NULL,
        score public.eql_v3_integer_ord_ore NOT NULL
      );
      CREATE INDEX eql_upgrade_email_idx
        ON eql_upgrade_records (eql_v3.eq_term(email));
      CREATE INDEX eql_upgrade_score_idx
        ON eql_upgrade_records (eql_v3.ord_term_ore(score));
    `)
    await client.query(
      `INSERT INTO eql_upgrade_records VALUES
        (1, $1::jsonb, $2::jsonb), (2, $3::jsonb, $4::jsonb)`,
      rows,
    )
  }, 180_000)

  afterAll(async () => {
    await client
      .query('DROP TABLE IF EXISTS eql_upgrade_records')
      .catch(() => undefined)
    await client.end().catch(() => undefined)
  })

  it('upgrades a released installation while preserving usable encrypted indexes', async () => {
    await new EQLInstaller({ databaseUrl: DATABASE_URL ?? '' }).install()

    const emailOperand = await encryptQuery(protectClient, {
      plaintext: 'bob@example.com',
      column: 'email',
      table: 'eql_upgrade_records',
      indexType: 'unique',
    })
    const scoreOperand = await encryptQuery(protectClient, {
      plaintext: 15,
      column: 'score',
      table: 'eql_upgrade_records',
      indexType: 'ore',
    })
    const result = await client.query<{
      email: EncryptedPayload
      score: EncryptedPayload
    }>(
      `SELECT email::jsonb, score::jsonb FROM eql_upgrade_records
       WHERE email = $1::jsonb::eql_v3.query_text_eq
         AND score > $2::jsonb::eql_v3.query_integer_ord_ore`,
      [emailOperand, scoreOperand],
    )
    expect(
      await decryptBulk(protectClient, {
        ciphertexts: result.rows.flatMap(({ email, score }) => [
          { ciphertext: email },
          { ciphertext: score },
        ]),
      }),
    ).toEqual(['bob@example.com', 20])

    const indexes = await client.query<{ relname: string; valid: boolean }>(`
      SELECT c.relname, i.indisvalid AS valid
      FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
      WHERE c.relname IN ('eql_upgrade_email_idx', 'eql_upgrade_score_idx')
      ORDER BY c.relname
    `)
    expect(indexes.rows).toEqual([
      { relname: 'eql_upgrade_email_idx', valid: true },
      { relname: 'eql_upgrade_score_idx', valid: true },
    ])

    await client.query('SET enable_seqscan = off')
    try {
      const emailPlan = await client.query<{ 'QUERY PLAN': string }>(
        `EXPLAIN (COSTS OFF)
         SELECT id FROM eql_upgrade_records
         WHERE eql_v3.eq_term(email) =
           eql_v3.eq_term($1::jsonb::eql_v3.query_text_eq)`,
        [emailOperand],
      )
      const scorePlan = await client.query<{ 'QUERY PLAN': string }>(
        `EXPLAIN (COSTS OFF)
         SELECT id FROM eql_upgrade_records
         WHERE eql_v3.ord_term_ore(score) >
           eql_v3.ord_term_ore($1::jsonb::eql_v3.query_integer_ord_ore)`,
        [scoreOperand],
      )
      expect(
        emailPlan.rows.map((row) => row['QUERY PLAN']).join('\n'),
      ).toContain('eql_upgrade_email_idx')
      expect(
        scorePlan.rows.map((row) => row['QUERY PLAN']).join('\n'),
      ).toContain('eql_upgrade_score_idx')
    } finally {
      await client.query('RESET enable_seqscan')
    }
  }, 180_000)
})
