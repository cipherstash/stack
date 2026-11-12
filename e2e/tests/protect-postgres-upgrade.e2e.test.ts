import { spawn } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
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
    expect(await app.find('v2', 'email', 'ada@example.com')).toEqual(['ada'])
    expect(await app.find('v2', 'email', 'nobody@example.com')).toEqual([])
    const before =
      await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM ${sql(table)} ORDER BY pk`
    expect(before[0].email.v).toBe(2)
    await app.migrate()
    expect(await app.read('v3')).toEqual(app.corpus)
    expect(await app.find('v3', 'age', 36)).toEqual(['ada', 'alan'])
    expect(await app.find('v3', 'email', 'ada@example.com')).toEqual(['ada'])
    expect(await app.find('v3', 'email', 'nobody@example.com')).toEqual([])
    const after =
      await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes,
      email_v3::jsonb AS email_v3, age_v3::jsonb AS age_v3, notes_v3::jsonb AS notes_v3 FROM ${sql(table)} ORDER BY pk`
    for (let i = 0; i < before.length; i++) {
      for (const column of ['email', 'age', 'notes']) {
        expect(after[i][column]).toEqual(before[i][column])
        expect(after[i][`${column}_v3`].c).toBe(before[i][column].c)
        expect(after[i][`${column}_v3`].hm ?? null).toBe(
          before[i][column].hm ?? null,
        )
      }
    }
    await app.rollback()
    expect(await app.read('v2')).toEqual(app.corpus)
    expect(
      await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM ${sql(table)} ORDER BY pk`,
    ).toEqual(before)
  }, 120_000)

  it('runs the standalone guide script against Protect-written source columns', async () => {
    const guide = await readFile(
      new URL(
        '../../docs/migration/protect-dynamodb-to-stack.md',
        import.meta.url,
      ),
      'utf8',
    )
    const snippet = [...guide.matchAll(/```typescript\n([\s\S]*?)\n```/g)]
      .map((match) => match[1])
      .find((code) => code.includes('ACCESS EXCLUSIVE'))
    expect(snippet).toBeDefined()
    if (!snippet) throw new Error('Missing standalone conversion')
    // The temporary sibling resolves the same installed packages as the npm
    // example. Execute the guide verbatim, including its real CLI entry point.
    const directory = await mkdtemp(
      fileURLToPath(new URL('../.guide-script-', import.meta.url)),
    )
    try {
      const script = `${directory}/migrate.ts`
      await writeFile(script, snippet)
      const exitCode = await new Promise<number | null>((resolve, reject) => {
        const child = spawn(process.execPath, [script], {
          env: {
            ...process.env,
            DATABASE_URL: databaseUrl,
            MIGRATION_TABLE: table,
          },
          stdio: 'ignore',
          timeout: 110_000,
        })
        child.once('error', reject)
        child.once('exit', resolve)
      })
      expect(
        exitCode,
        'standalone guide conversion must commit successfully',
      ).toBe(0)
      expect(await app.read('v3')).toEqual(app.corpus)
      expect(await app.find('v3', 'age', 36)).toEqual(['ada', 'alan'])
      await app.rollback()
      expect(await app.read('v2')).toEqual(app.corpus)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
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
      await sql`SELECT email_v3::jsonb AS email_v3, age_v3::jsonb AS age_v3 FROM ${sql(table)} WHERE pk = 'ada'`
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

  it('accepts the supported shape after a physical column before pk was dropped', async () => {
    const relation = `public.${table}`
    const replacement = `public.${table}_replacement`
    await sql.begin(async (tx) => {
      await tx`CREATE TABLE ${tx(replacement)} (
        discarded text, pk text PRIMARY KEY,
        email public.eql_v2_encrypted,
        age public.eql_v2_encrypted,
        notes public.eql_v2_encrypted
      )`
      await tx`INSERT INTO ${tx(replacement)} (pk, email, age, notes)
        SELECT pk, email, age, notes FROM ${tx(relation)}`
      await tx`ALTER TABLE ${tx(replacement)} DROP COLUMN discarded`
      await tx`DROP TABLE ${tx(relation)}`
      await tx`ALTER TABLE ${tx(replacement)} RENAME TO ${tx(table)}`
    })
    const [fixture] =
      await sql`SELECT pg_catalog.to_regclass(${relation})::text AS relation`
    expect(
      fixture.relation,
      'fixture must create the public migration source',
    ).not.toBeNull()
    const attributes = await sql`SELECT attnum FROM pg_catalog.pg_attribute
      WHERE attrelid = pg_catalog.to_regclass(${relation}) AND attname = 'pk' AND NOT attisdropped`
    expect(
      attributes.map((attribute) => attribute.attnum),
      'pk must retain physical attribute 2 after its predecessor is dropped',
    ).toEqual([2])
    await app.migrate()
    expect(await app.read('v3')).toEqual(app.corpus)
    await app.rollback()
    expect(await app.read('v2')).toEqual(app.corpus)
  }, 120_000)

  it.each(['pg_catalog', 'eql_v3,pg_catalog'])(
    'accepts the supported public table with search_path %s',
    async (searchPath) => {
      const restricted = postgres(databaseUrl, {
        prepare: false,
        max: 1,
        onnotice: () => {},
        connection: { search_path: searchPath },
      })
      try {
        const restrictedApp = await createExample(restricted, table)
        await restrictedApp.migrate()
        expect(await restrictedApp.read('v3')).toEqual(app.corpus)
        expect(await restrictedApp.find('v3', 'age', 36)).toEqual([
          'ada',
          'alan',
        ])
        expect(
          await restrictedApp.find('v3', 'email', 'nobody@example.com'),
        ).toEqual([])
        await restrictedApp.rollback()
        expect(await restrictedApp.read('v2')).toEqual(app.corpus)
      } finally {
        await restricted.end()
      }
    },
    120_000,
  )

  it('refuses a source table without the required primary key', async () => {
    await sql`ALTER TABLE ${sql(table)} DROP CONSTRAINT ${sql(`${table}_pkey`)}`
    const before = await sql`SELECT * FROM ${sql(table)} ORDER BY pk`
    await expect(app.migrate()).rejects.toThrow(
      'Unsupported table dependencies',
    )
    expect(await sql`SELECT * FROM ${sql(table)} ORDER BY pk`).toEqual(before)
    expect(
      await sql`SELECT attname FROM pg_attribute WHERE attrelid = ${table}::regclass AND attname = 'email_v3'`,
    ).toHaveLength(0)
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

  // Stack writes leave the legacy columns null, so a NOT NULL there would fail
  // every write after cutover. PostgreSQL 18 lists NOT NULL in pg_constraint
  // and 17 does not; the preflight must give the same answer on both.
  it('refuses a NOT NULL legacy column before changing source data or columns', async () => {
    await sql`ALTER TABLE ${sql(table)} ALTER COLUMN email SET NOT NULL`
    const before = await sql`SELECT * FROM ${sql(table)} ORDER BY pk`
    await expect(app.migrate()).rejects.toThrow(
      'Unsupported table dependencies',
    )
    expect(await sql`SELECT * FROM ${sql(table)} ORDER BY pk`).toEqual(before)
    expect(
      await sql`SELECT attname FROM pg_attribute WHERE attrelid = ${table}::regclass AND attname = 'email_v3'`,
    ).toHaveLength(0)
  }, 120_000)

  it.each(['constraint', 'not-null', 'index'])(
    'refuses rollback that would discard a customer %s',
    async (dependency) => {
      await app.migrate()
      if (dependency === 'constraint') {
        await sql`ALTER TABLE ${sql(table)} ADD CONSTRAINT customer_check CHECK (email_v3 IS NOT NULL)`
      } else if (dependency === 'not-null') {
        await sql`ALTER TABLE ${sql(table)} ALTER COLUMN email_v3 SET NOT NULL`
      } else {
        await sql`CREATE INDEX ${sql(`${table}_custom`)} ON ${sql(table)} (eql_v3.eq_term(email_v3))`
      }
      const before = await sql`SELECT * FROM ${sql(table)} ORDER BY pk`
      await expect(app.rollback()).rejects.toThrow(
        'Unsupported table dependencies',
      )
      expect(await sql`SELECT * FROM ${sql(table)} ORDER BY pk`).toEqual(before)
      if (dependency === 'constraint') {
        expect(
          await sql`SELECT 1 FROM pg_constraint WHERE conrelid = ${table}::regclass AND conname = 'customer_check'`,
        ).toHaveLength(1)
      } else if (dependency === 'not-null') {
        expect(
          await sql`SELECT 1 FROM pg_attribute WHERE attrelid = ${table}::regclass AND attname = 'email_v3' AND attnotnull`,
        ).toHaveLength(1)
      } else {
        expect(
          await sql`SELECT 1 FROM pg_indexes WHERE tablename = ${table} AND indexname = ${`${table}_custom`}`,
        ).toHaveLength(1)
      }
    },
    120_000,
  )
})
