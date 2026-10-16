/**
 * Live-Postgres coverage for the SQL `stash decrypt plan` and
 * `stash decrypt drop` generate.
 *
 * The unit tests read the generated text; this suite EXECUTES it. The drop
 * migration nests identifiers inside an `EXECUTE '…'` string inside a
 * dollar-quoted `DO` block, so a quoting slip that every string assertion
 * accepts would still fail here — and an atomicity slip (a drop that runs
 * before its own coverage check has raised) is only observable on a real
 * server.
 *
 * Gated on STASH_TEST_DATABASE_URL so the default `pnpm test` stays green
 * without a database. Locally:
 *
 *   docker compose -f local/docker-compose.postgres.yml up -d --wait
 *   export STASH_TEST_DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash
 *
 * Needs no EQL install: `jsonb` stands in for the encrypted column (the SQL
 * under test never looks at its type), and the `--uninstall-eql` gate is
 * exercised with a probe domain in this suite's own schema and a harmless
 * stand-in statement, so the shared database's real EQL is never touched.
 */

import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

vi.mock('@/commands/encrypt/context.js', () => ({
  loadEncryptionContext: vi.fn(),
  requireTable: vi.fn(),
}))

import type pg from 'pg'
import { buildDecryptDropSql } from '../drop.js'
import { buildAddPlaintextSql } from '../plan.js'

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

const SCHEMA = 'stash_decrypt_live'
const TABLE = `${SCHEMA}.weird"users`
const QUOTED_TABLE = `"${SCHEMA}"."weird""users"`

describeLive('decrypt plan/drop SQL — live Postgres', () => {
  let client: pg.Client

  beforeAll(async () => {
    const { default: pgModule } = await import('pg')
    client = new pgModule.Client({ connectionString: DATABASE_URL })
    await client.connect()
  })

  afterAll(async () => {
    await client.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`)
    await client.end().catch(() => undefined)
  })

  beforeEach(async () => {
    await client.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`)
    await client.query(`CREATE SCHEMA ${SCHEMA}`)
    await client.query(`
      CREATE TABLE ${QUOTED_TABLE} (
        id int PRIMARY KEY,
        "o'brien_encrypted" jsonb
      )
    `)
    await client.query(
      `INSERT INTO ${QUOTED_TABLE} (id, "o'brien_encrypted")
       SELECT g, jsonb_build_object('v', 3, 'c', 'ct-' || g)
       FROM generate_series(1, 5) AS g`,
    )
    // An EQL-shaped functional index: it references the column only through
    // its expression.
    await client.query(
      `CREATE INDEX "weird idx" ON ${QUOTED_TABLE} (("o'brien_encrypted"->>'c'))`,
    )
  })

  async function columns(): Promise<string[]> {
    const { rows } = await client.query<{ attname: string }>(
      `SELECT attname FROM pg_attribute
        WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped
        ORDER BY attnum`,
      [QUOTED_TABLE],
    )
    return rows.map((row) => row.attname)
  }

  async function addTwinAndFill(skipId?: number) {
    await client.query(
      buildAddPlaintextSql(TABLE, [
        {
          encryptedColumn: "o'brien_encrypted",
          domain: 'eql_v3_text',
          plaintextColumn: 'o"brien',
          mapping: { sqlType: 'text' },
        },
      ]),
    )
    await client.query(
      `UPDATE ${QUOTED_TABLE} SET "o""brien" = "o'brien_encrypted"->>'c'
        WHERE id IS DISTINCT FROM $1`,
      [skipId ?? null],
    )
  }

  const dropSql = (uninstallStatements: string[] = []) =>
    buildDecryptDropSql({
      table: TABLE,
      encryptedColumn: "o'brien_encrypted",
      plaintextColumn: 'o"brien',
      indexes: [{ schema: SCHEMA, name: 'weird idx', definition: '' }],
      uninstallStatements,
    })

  it('plan: the twin migration applies, and re-applies as a no-op', async () => {
    await addTwinAndFill()
    await addTwinAndFill()
    expect(await columns()).toEqual(['id', "o'brien_encrypted", 'o"brien'])
  })

  it('drop: removes the index and the encrypted column, keeps the plaintext', async () => {
    await addTwinAndFill()

    await client.query(dropSql())

    expect(await columns()).toEqual(['id', 'o"brien'])
    const { rows } = await client.query(
      `SELECT 1 FROM pg_class WHERE relname = 'weird idx'`,
    )
    expect(rows).toHaveLength(0)
  })

  it('drop: an undecrypted row aborts the whole migration — nothing is dropped', async () => {
    await addTwinAndFill(3)

    await expect(client.query(dropSql())).rejects.toThrow(
      /refusing to drop .* 1 row\(s\) have ciphertext set/,
    )
    expect(await columns()).toEqual(['id', "o'brien_encrypted", 'o"brien'])
    const { rows } = await client.query(
      `SELECT 1 FROM pg_class WHERE relname = 'weird idx'`,
    )
    expect(rows).toHaveLength(1)
  })

  it('drop --uninstall-eql: another EQL v3 column anywhere aborts it, leaving the column in place', async () => {
    await addTwinAndFill()
    await client.query(`CREATE DOMAIN ${SCHEMA}.eql_v3_probe AS jsonb`)
    await client.query(
      `CREATE TABLE ${SCHEMA}.other (id int, secret ${SCHEMA}.eql_v3_probe)`,
    )

    await expect(
      client.query(dropSql([`CREATE TABLE ${SCHEMA}.uninstall_ran (x int)`])),
    ).rejects.toThrow(
      /refusing to uninstall EQL — \d+ EQL v3 column\(s\) still exist/,
    )
    expect(await columns()).toEqual(['id', "o'brien_encrypted", 'o"brien'])
    const { rows } = await client.query(
      `SELECT to_regclass('${SCHEMA}.uninstall_ran') AS ran`,
    )
    expect(rows[0]?.ran).toBeNull()
  })
})
