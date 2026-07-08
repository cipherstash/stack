import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'
import type { Encrypted } from '@/types'
import { unwrapResult } from './fixtures'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import { describeLivePg, LIVE_EQL_V3_PG_ENABLED } from './helpers/live-gate'

const databaseUrl = process.env.DATABASE_URL
const sql = LIVE_EQL_V3_PG_ENABLED
  ? postgres(databaseUrl as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

const table = encryptedTable('protect_ci_v3_text_search', {
  email: types.TextSearch('email'),
})

const typedTable = encryptedTable('protect_ci_v3_typed_domains', {
  age: types.IntegerOrd('age'),
  nickname: types.TextEq('nickname'),
  active: types.Boolean('active'),
})

const TEST_RUN_ID = `test-run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

type InsertedRow = {
  id: number
  email: unknown
  label: string
}

type EncryptionPayload = postgres.JSONValue

let protectClient: EncryptionClient

async function encryptValue(value: string): Promise<EncryptionPayload> {
  return unwrapResult(
    await protectClient.encrypt(value, {
      table,
      column: table.email,
    }),
  ) as EncryptionPayload
}

async function encryptQueryTerm(
  value: string,
  queryType?: 'equality' | 'freeTextSearch' | 'orderAndRange',
): Promise<EncryptionPayload> {
  return unwrapResult(
    await protectClient.encryptQuery(value, {
      table,
      column: table.email,
      queryType,
    }),
  ) as EncryptionPayload
}

async function insertRow(label: string, email: string): Promise<number> {
  const encrypted = await encryptValue(email)

  const [inserted] = await sql<{ id: number }[]>`
    INSERT INTO protect_ci_v3_text_search (email, label, test_run_id)
    VALUES (${sql.json(encrypted)}::eql_v3.text_search, ${label}, ${TEST_RUN_ID})
    RETURNING id
  `

  return inserted.id
}

async function decryptRow(row: InsertedRow): Promise<string> {
  const decrypted = unwrapResult(
    await protectClient.decrypt(row.email as Encrypted),
  )
  expect(typeof decrypted).toBe('string')
  return decrypted as string
}

async function seedRows(): Promise<Record<string, number>> {
  const rows = {
    ada: await insertRow('ada', 'ada@example.com'),
    grace: await insertRow('grace', 'grace@example.com'),
    alan: await insertRow('alan', 'alan@example.net'),
    zora: await insertRow('zora', 'zora@example.org'),
  }

  return rows
}

beforeAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return

  await installEqlV3IfNeeded(sql)
  protectClient = await Encryption({ schemas: [table, typedTable] })

  await sql`
    CREATE TABLE IF NOT EXISTS protect_ci_v3_text_search (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      email eql_v3.text_search NOT NULL,
      label TEXT NOT NULL,
      test_run_id TEXT NOT NULL
    )
  `

  await sql`
    CREATE TABLE IF NOT EXISTS protect_ci_v3_typed_domains (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      age eql_v3.integer_ord NOT NULL,
      nickname eql_v3.text_eq NOT NULL,
      active eql_v3.boolean NOT NULL,
      test_run_id TEXT NOT NULL
    )
  `
}, 30000)

beforeEach(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return

  await sql`
    DELETE FROM protect_ci_v3_text_search
    WHERE test_run_id = ${TEST_RUN_ID}
  `
  await sql`
    DELETE FROM protect_ci_v3_typed_domains
    WHERE test_run_id = ${TEST_RUN_ID}
  `
}, 30000)

afterAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return

  await sql`
    DELETE FROM protect_ci_v3_text_search
    WHERE test_run_id = ${TEST_RUN_ID}
  `
  await sql`
    DELETE FROM protect_ci_v3_typed_domains
    WHERE test_run_id = ${TEST_RUN_ID}
  `
  await sql.end()
}, 30000)

describeLivePg('eql_v3 text_search postgres integration', () => {
  it('round-trips an encrypted value through an eql_v3.text_search column', async () => {
    const id = await insertRow('roundtrip', 'roundtrip@example.com')

    const [row] = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE id = ${id}
    `

    expect(row).toBeDefined()
    await expect(decryptRow(row)).resolves.toBe('roundtrip@example.com')
  }, 30000)

  it('queries equality terms with eql_v3.eq_term and eql_v3.hmac_256', async () => {
    const ids = await seedRows()
    const equalityTerm = await encryptQueryTerm('grace@example.com', 'equality')

    const rows = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.eq_term(email) = eql_v3.hmac_256(${sql.json(equalityTerm)}::jsonb)
      ORDER BY id
    `

    expect(rows.map((row) => row.id)).toEqual([ids.grace])
    await expect(decryptRow(rows[0])).resolves.toBe('grace@example.com')
  }, 30000)

  it('queries free-text terms with eql_v3.match_term and eql_v3.bloom_filter', async () => {
    await seedRows()
    const matchTerm = await encryptQueryTerm('example.com', 'freeTextSearch')

    const rows = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.match_term(email) @> eql_v3.bloom_filter(${sql.json(matchTerm)}::jsonb)
      ORDER BY label
    `

    expect(rows.map((row) => row.label)).toEqual(['ada', 'grace'])
  }, 30000)

  it('queries range terms with eql_v3.ord_term and eql_v3.ore_block_256', async () => {
    await seedRows()
    const lower = await encryptQueryTerm('grace@example.com', 'orderAndRange')
    const upper = await encryptQueryTerm('zora@example.org', 'orderAndRange')

    const rows = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.ord_term(email) >= eql_v3.ore_block_256(${sql.json(lower)}::jsonb)
        AND eql_v3.ord_term(email) <= eql_v3.ore_block_256(${sql.json(upper)}::jsonb)
      ORDER BY eql_v3.ord_term(email)
    `

    expect(rows.map((row) => row.label)).toEqual(['grace', 'zora'])
  }, 30000)

  it('creates functional indexes for equality, match, and order terms', async () => {
    await sql`
      CREATE INDEX IF NOT EXISTS protect_ci_v3_text_search_email_eq_idx
      ON protect_ci_v3_text_search USING btree (eql_v3.eq_term(email))
    `
    await sql`
      CREATE INDEX IF NOT EXISTS protect_ci_v3_text_search_email_match_idx
      ON protect_ci_v3_text_search USING gin (eql_v3.match_term(email))
    `
    await sql`
      CREATE INDEX IF NOT EXISTS protect_ci_v3_text_search_email_ord_idx
      ON protect_ci_v3_text_search USING btree (eql_v3.ord_term(email))
    `

    const indexes = await sql<{ indexname: string; indexdef: string }[]>`
      SELECT indexname, indexdef
      FROM pg_indexes
      WHERE schemaname = 'public'
        AND tablename = 'protect_ci_v3_text_search'
        AND indexname IN (
          'protect_ci_v3_text_search_email_eq_idx',
          'protect_ci_v3_text_search_email_match_idx',
          'protect_ci_v3_text_search_email_ord_idx'
        )
    `

    expect(indexes).toHaveLength(3)
    expect(indexes.map((idx) => idx.indexdef).join('\n')).toContain(
      'eql_v3.eq_term',
    )
    expect(indexes.map((idx) => idx.indexdef).join('\n')).toContain(
      'eql_v3.match_term',
    )
    expect(indexes.map((idx) => idx.indexdef).join('\n')).toContain(
      'eql_v3.ord_term',
    )
  }, 30000)

  it('rejects query-only payloads cast as eql_v3.text_search values', async () => {
    const equalityTerm = await encryptQueryTerm('ada@example.com', 'equality')

    await expect(
      sql`
        INSERT INTO protect_ci_v3_text_search (email, label, test_run_id)
        VALUES (
          ${sql.json(equalityTerm)}::eql_v3.text_search,
          'query-only',
          ${TEST_RUN_ID}
        )
      `,
    ).rejects.toThrow()
  }, 30000)

  it('round-trips and queries representative typed v3 domains', async () => {
    const age = unwrapResult(
      await protectClient.encrypt(37, {
        table: typedTable,
        column: typedTable.age,
      }),
    )
    const nickname = unwrapResult(
      await protectClient.encrypt('ada', {
        table: typedTable,
        column: typedTable.nickname,
      }),
    )
    const active = unwrapResult(
      await protectClient.encrypt(true, {
        table: typedTable,
        column: typedTable.active,
      }),
    )

    const [inserted] = await sql<{ id: number }[]>`
      INSERT INTO protect_ci_v3_typed_domains (age, nickname, active, test_run_id)
      VALUES (
        ${sql.json(age as postgres.JSONValue)}::eql_v3.integer_ord,
        ${sql.json(nickname as postgres.JSONValue)}::eql_v3.text_eq,
        ${sql.json(active as postgres.JSONValue)}::eql_v3.boolean,
        ${TEST_RUN_ID}
      )
      RETURNING id
    `

    const ageTerm = unwrapResult(
      await protectClient.encryptQuery(30, {
        table: typedTable,
        column: typedTable.age,
        queryType: 'orderAndRange',
      }),
    ) as postgres.JSONValue

    const rows = await sql<{ id: number }[]>`
      SELECT id
      FROM protect_ci_v3_typed_domains
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.ord_term(age) >= eql_v3.ore_block_256(${sql.json(ageTerm)}::jsonb)
    `

    expect(rows.map((row) => row.id)).toContain(inserted.id)
  }, 30000)

  // Correctness proof for the equality-via-ORE fix (Part A). The deterministic
  // regression proves `resolveIndexType` resolves equality to `ore` instead of
  // throwing; this proves the resulting term actually SELECTS the right rows
  // against real Postgres, using the SQL `=` operator on the ORE term.
  it('selects the exact row for an equality term via ORE on an integer_ord column', async () => {
    async function insertAge(age: number): Promise<number> {
      const ageCt = unwrapResult(
        await protectClient.encrypt(age, {
          table: typedTable,
          column: typedTable.age,
        }),
      ) as postgres.JSONValue
      const nick = unwrapResult(
        await protectClient.encrypt(`nick-${age}`, {
          table: typedTable,
          column: typedTable.nickname,
        }),
      ) as postgres.JSONValue
      const act = unwrapResult(
        await protectClient.encrypt(true, {
          table: typedTable,
          column: typedTable.active,
        }),
      ) as postgres.JSONValue
      const [row] = await sql<{ id: number }[]>`
        INSERT INTO protect_ci_v3_typed_domains (age, nickname, active, test_run_id)
        VALUES (
          ${sql.json(ageCt)}::eql_v3.integer_ord,
          ${sql.json(nick)}::eql_v3.text_eq,
          ${sql.json(act)}::eql_v3.boolean,
          ${TEST_RUN_ID}
        )
        RETURNING id
      `
      return row.id
    }

    const ids = {
      thirty: await insertAge(30),
      thirtySeven: await insertAge(37),
      fortyTwo: await insertAge(42),
    }

    // Equality term encrypted with queryType:'equality' — post-fix this resolves
    // to the ore (`ob`) term; the SQL `=` operator makes it an equality match.
    const equalityTerm = unwrapResult(
      await protectClient.encryptQuery(37, {
        table: typedTable,
        column: typedTable.age,
        queryType: 'equality',
      }),
    ) as postgres.JSONValue

    const matched = await sql<{ id: number }[]>`
      SELECT id
      FROM protect_ci_v3_typed_domains
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.ord_term(age) = eql_v3.ore_block_256(${sql.json(equalityTerm)}::jsonb)
      ORDER BY id
    `
    // Exactly the age=37 row — not the 30 or 42 rows.
    expect(matched.map((row) => row.id)).toEqual([ids.thirtySeven])
    expect(matched.map((row) => row.id)).not.toContain(ids.thirty)
    expect(matched.map((row) => row.id)).not.toContain(ids.fortyTwo)

    // A non-matching value selects nothing.
    const missTerm = unwrapResult(
      await protectClient.encryptQuery(99, {
        table: typedTable,
        column: typedTable.age,
        queryType: 'equality',
      }),
    ) as postgres.JSONValue
    const none = await sql<{ id: number }[]>`
      SELECT id
      FROM protect_ci_v3_typed_domains
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.ord_term(age) = eql_v3.ore_block_256(${sql.json(missTerm)}::jsonb)
    `
    expect(none).toHaveLength(0)
  }, 30000)
})
