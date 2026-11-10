import { installEqlV3 } from '@cipherstash/test-kit/install'
import postgres from 'postgres'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { createExample } from '../migration-guide/postgres.ts'
import { authConfigured } from './helpers/legacy-protect'

if (!authConfigured || !process.env.DATABASE_URL) {
  throw new Error(
    'protect-postgres-upgrade requires all four CS_* credentials and DATABASE_URL',
  )
}
const databaseUrl = process.env.DATABASE_URL

describe('Protect Postgres v2 to Stack v3', () => {
  const sql = postgres(databaseUrl, { prepare: false, onnotice: () => {} })
  const table = `upgrade_${Date.now()}`
  let app: Awaited<ReturnType<typeof createExample>>

  beforeAll(async () => {
    // Only a disposable test database: customers already have v2 installed.
    const installed =
      await sql`SELECT to_regtype('public.eql_v2_encrypted') AS type`
    if (!installed[0].type) {
      const response = await fetch(
        'https://github.com/cipherstash/encrypt-query-language/releases/download/eql-2.2.1/cipherstash-encrypt.sql',
      )
      if (!response.ok)
        throw new Error(`EQL v2 download failed: ${response.status}`)
      await sql.unsafe(await response.text())
    }
    await installEqlV3(databaseUrl, 'postgres')
    app = await createExample(sql, table)
  }, 180_000)

  afterAll(async () => {
    await sql`DROP TABLE IF EXISTS ${sql(table)}`
    await sql.end()
  })

  beforeEach(async () => {
    await sql`DROP TABLE IF EXISTS ${sql(table)}`
    await app.seed()
  }, 120_000)

  it('migrates actual v2 columns, preserves ciphertext and queries, and rolls back before writes resume', async () => {
    expect(await app.read('v2')).toEqual(app.corpus)
    expect(await app.find('v2', 'age', 36)).toEqual(['ada', 'alan'])
    const before = await sql`SELECT * FROM ${sql(table)} ORDER BY pk`
    expect(before[0].email.v).toBe(2)
    await app.migrate()
    expect(await app.read('v3')).toEqual(app.corpus)
    expect(await app.find('v3', 'age', 36)).toEqual(['ada', 'alan'])
    expect(await app.find('v3', 'email', 'nobody@example.com')).toEqual([])
    const after = await sql`SELECT * FROM ${sql(table)} ORDER BY pk`
    for (let i = 0; i < before.length; i++) {
      for (const column of ['email', 'age', 'notes']) {
        expect(after[i][column]).toEqual(before[i][column])
        expect(after[i][`${column}_v3`].c).toBe(before[i][column].c)
        expect(after[i][`${column}_v3`].hm).toBe(before[i][column].hm)
      }
    }
    await app.rollback()
    expect(await app.read('v2')).toEqual(app.corpus)
    expect(await sql`SELECT * FROM ${sql(table)} ORDER BY pk`).toEqual(before)
  }, 120_000)

  it('reads and queries fresh Stack writes beside legacy rows and refuses stale rollback', async () => {
    await app.migrate()
    const fresh = await app.write()
    expect(await app.read('v3')).toEqual([...app.corpus, fresh])
    expect(await app.find('v3', 'age', 36)).toEqual(['ada', 'alan', 'new'])
    expect(await app.find('v3', 'email', fresh.email)).toEqual(['new'])
    await expect(app.rollback()).rejects.toThrow('Writes have resumed')
    expect(await app.read('v3')).toEqual([...app.corpus, fresh])
  }, 120_000)

  it('creates usable equality indexes on the converted columns', async () => {
    await app.migrate()
    // A selective query needs a representative table, not a forced planner flag.
    await sql`INSERT INTO ${sql(table)}
      SELECT 'filler-' || n, email, age, notes, email_v3, age_v3, notes_v3
      FROM ${sql(table)}, generate_series(1, 5000) n WHERE pk = 'grace'`
    await sql`ANALYZE ${sql(table)}`
    const [ada] =
      await sql`SELECT email_v3, age_v3 FROM ${sql(table)} WHERE pk = 'ada'`
    const emailPlan =
      await sql`EXPLAIN (FORMAT JSON) SELECT pk FROM ${sql(table)}
      WHERE eql_v3.eq(email_v3, ${sql.json(ada.email_v3)}::jsonb::eql_v3.query_text_eq)`
    const agePlan = await sql`EXPLAIN (FORMAT JSON) SELECT pk FROM ${sql(table)}
      WHERE eql_v3.eq(age_v3, ${sql.json(ada.age_v3)}::jsonb::eql_v3.query_integer_eq)`
    expect(JSON.stringify(emailPlan)).toContain(`${table}_email_v3_idx`)
    expect(JSON.stringify(agePlan)).toContain(`${table}_age_v3_idx`)
    expect(await app.find('v3', 'email', 'ada@example.com')).toEqual(['ada'])
    expect(await app.find('v3', 'age', 36)).toEqual(['ada', 'alan'])
  }, 120_000)

  it('refuses unsupported payload capabilities before changing source data or columns', async () => {
    await sql`UPDATE ${sql(table)} SET notes = notes::jsonb || '{"ob":"unsupported"}'::jsonb WHERE pk = 'ada'`
    const before = await sql`SELECT * FROM ${sql(table)} ORDER BY pk`
    await expect(app.migrate()).rejects.toThrow('Unsupported legacy payload')
    expect(await sql`SELECT * FROM ${sql(table)} ORDER BY pk`).toEqual(before)
    expect(
      await sql`SELECT attname FROM pg_attribute WHERE attrelid = ${table}::regclass AND attname = 'email_v3'`,
    ).toHaveLength(0)
  }, 120_000)

  it('refuses customer views before changing source data or columns', async () => {
    await sql`CREATE VIEW ${sql(`${table}_view`)} AS SELECT email FROM ${sql(table)}`
    try {
      const before = await sql`SELECT * FROM ${sql(table)} ORDER BY pk`
      await expect(app.migrate()).rejects.toThrow(
        'Unsupported table dependencies',
      )
      expect(await sql`SELECT * FROM ${sql(table)} ORDER BY pk`).toEqual(before)
      expect(
        await sql`SELECT attname FROM pg_attribute WHERE attrelid = ${table}::regclass AND attname = 'email_v3'`,
      ).toHaveLength(0)
    } finally {
      await sql`DROP VIEW ${sql(`${table}_view`)}`
    }
  }, 120_000)
})
