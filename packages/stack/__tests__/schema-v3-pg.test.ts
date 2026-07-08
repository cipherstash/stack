import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, beforeEach, expect, it } from 'vitest'
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

// A query operand under EQL v3 is a FULL encrypted payload — the same thing
// `client.encrypt` produces for storage — NOT an `encryptQuery` term (protect-ffi
// 0.28 has no v3 scalar query wire shape; `encryptQuery` throws
// EQL_V3_QUERY_UNSUPPORTED). Compare it to a column with the public two-arg
// `eql_v3.*(col, operand::jsonb)` functions; the operand carries every index
// term, so which SQL function you call selects which term is compared.
async function encryptOperand(
  value: unknown,
  opts: Parameters<EncryptionClient['encrypt']>[1],
): Promise<EncryptionPayload> {
  return unwrapResult(
    await protectClient.encrypt(value as never, opts),
  ) as EncryptionPayload
}

async function insertRow(label: string, email: string): Promise<number> {
  const encrypted = await encryptValue(email)

  const [inserted] = await sql<{ id: number }[]>`
    INSERT INTO protect_ci_v3_text_search (email, label, test_run_id)
    VALUES (${sql.json(encrypted)}::public.text_search, ${label}, ${TEST_RUN_ID})
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
  // `eqlVersion: 3` is required for v3 concrete-type schemas: protect-ffi's
  // newClient defaults to v2, and a v2-mode client cannot encrypt these columns
  // (it throws "Cannot convert undefined or null to object"). EncryptionV3 sets
  // this automatically; the base `Encryption` factory does not, so pass it here.
  protectClient = await Encryption({
    schemas: [table, typedTable],
    config: { eqlVersion: 3 },
  })

  // DROP first: these tables are created with IF NOT EXISTS and cleaned up by
  // row DELETE only, so one left by an earlier local run keeps its OLD column
  // domain types across the `eql_v3.* -> public.*` rename — silently testing a
  // stale schema. Harmless in CI (fresh Postgres); reliable local reruns.
  await sql`DROP TABLE IF EXISTS protect_ci_v3_text_search`
  await sql`DROP TABLE IF EXISTS protect_ci_v3_typed_domains`

  await sql`
    CREATE TABLE IF NOT EXISTS protect_ci_v3_text_search (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      email public.text_search NOT NULL,
      label TEXT NOT NULL,
      test_run_id TEXT NOT NULL
    )
  `

  await sql`
    CREATE TABLE IF NOT EXISTS protect_ci_v3_typed_domains (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      age public.integer_ord NOT NULL,
      nickname public.text_eq NOT NULL,
      active public.boolean NOT NULL,
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
  it('round-trips an encrypted value through an public.text_search column', async () => {
    const id = await insertRow('roundtrip', 'roundtrip@example.com')

    const [row] = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE id = ${id}
    `

    expect(row).toBeDefined()
    await expect(decryptRow(row)).resolves.toBe('roundtrip@example.com')
  }, 30000)

  it('queries equality with eql_v3.eq and a full operand', async () => {
    const ids = await seedRows()
    const operand = await encryptOperand('grace@example.com', {
      table,
      column: table.email,
    })

    const rows = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.eq(email, ${sql.json(operand)}::jsonb)
      ORDER BY id
    `

    expect(rows.map((row) => row.id)).toEqual([ids.grace])
    await expect(decryptRow(rows[0])).resolves.toBe('grace@example.com')
  }, 30000)

  it('queries free-text with eql_v3.contains and a full operand', async () => {
    await seedRows()
    const operand = await encryptOperand('example.com', {
      table,
      column: table.email,
    })

    const rows = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.contains(email, ${sql.json(operand)}::jsonb)
      ORDER BY label
    `

    expect(rows.map((row) => row.label)).toEqual(['ada', 'grace'])
  }, 30000)

  it('queries range with eql_v3.gte/lte and full operands', async () => {
    await seedRows()
    const lower = await encryptOperand('grace@example.com', {
      table,
      column: table.email,
    })
    const upper = await encryptOperand('zora@example.org', {
      table,
      column: table.email,
    })

    const rows = await sql<InsertedRow[]>`
      SELECT id, email::jsonb AS email, label
      FROM protect_ci_v3_text_search
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.gte(email, ${sql.json(lower)}::jsonb)
        AND eql_v3.lte(email, ${sql.json(upper)}::jsonb)
      ORDER BY label
    `

    // Assert range MEMBERSHIP deterministically by ordering on the plaintext
    // `label`. The range predicate above (eql_v3.gte/lte) already proves the ORE
    // comparison is lexically correct: it selects grace+zora and excludes
    // ada/alan.
    //
    // NB: we deliberately do NOT order by `eql_v3.ord_term(email)` (nor by the
    // `email` column, nor `email USING <`). None of those yield ORE order on a
    // non-superuser Postgres: `ord_term` returns the composite
    // `eql_v3_internal.ore_block_256`, whose ORE-aware btree opclass is
    // superuser-gated and skipped on managed installs, so `ORDER BY ord_term`
    // silently falls back to PostgreSQL's built-in record comparison (raw-byte
    // order, not ORE). See docs/eql-v3-ord-term-ordering-defect.md.
    expect(rows.map((row) => row.label)).toEqual(['grace', 'zora'])
  }, 30000)

  it('proves ORE total order via pairwise eql_v3.lt (ord_term ORDER BY is NOT ORE order)', async () => {
    // The ORE comparison operators are ORE-correct even where `ORDER BY
    // ord_term(col)` is not (see docs/eql-v3-ord-term-ordering-defect.md).
    // Reconstruct the total order purely from boolean `eql_v3.lt` predicates: a
    // self cross-join gives, for each ordered pair, whether x < y under ORE; the
    // count of rows a label is strictly-less-than is its ascending rank.
    await seedRows()

    const pairs = await sql<{ a: string; b: string; lt: boolean }[]>`
      SELECT x.label AS a, y.label AS b, eql_v3.lt(x.email, y.email) AS lt
      FROM protect_ci_v3_text_search x
      CROSS JOIN protect_ci_v3_text_search y
      WHERE x.test_run_id = ${TEST_RUN_ID}
        AND y.test_run_id = ${TEST_RUN_ID}
        AND x.label <> y.label
    `

    const labels = ['ada', 'grace', 'alan', 'zora']
    const lessThanCount = new Map<string, number>(labels.map((l) => [l, 0]))
    for (const pair of pairs) {
      if (pair.lt) lessThanCount.set(pair.a, (lessThanCount.get(pair.a) ?? 0) + 1)
    }

    const ascending = [...lessThanCount.entries()]
      .sort(([, aRank], [, bRank]) => bRank - aRank)
      .map(([label]) => label)

    // Lexical/ORE order of the seeded emails:
    //   ada@example.com < alan@example.net < grace@example.com < zora@example.org
    expect(ascending).toEqual(['ada', 'alan', 'grace', 'zora'])
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

  it('rejects a ciphertext-less payload cast as a public.text_search value', async () => {
    // A full operand with its ciphertext (`c`) removed mimics a query-only
    // payload: index terms present, no stored value. The domain CHECK must
    // reject it, so it can never masquerade as a stored ciphertext.
    const full = (await encryptOperand('ada@example.com', {
      table,
      column: table.email,
    })) as Record<string, unknown>
    const { c: _ciphertext, ...ciphertextLess } = full

    await expect(
      sql`
        INSERT INTO protect_ci_v3_text_search (email, label, test_run_id)
        VALUES (
          ${sql.json(ciphertextLess as EncryptionPayload)}::public.text_search,
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
        ${sql.json(age as postgres.JSONValue)}::public.integer_ord,
        ${sql.json(nickname as postgres.JSONValue)}::public.text_eq,
        ${sql.json(active as postgres.JSONValue)}::public.boolean,
        ${TEST_RUN_ID}
      )
      RETURNING id
    `

    const ageTerm = await encryptOperand(30, {
      table: typedTable,
      column: typedTable.age,
    })

    const rows = await sql<{ id: number }[]>`
      SELECT id
      FROM protect_ci_v3_typed_domains
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.gte(age, ${sql.json(ageTerm)}::jsonb)
    `

    expect(rows.map((row) => row.id)).toContain(inserted.id)
  }, 30000)

  // Correctness proof for equality-via-ORE on an `integer_ord` column. The
  // `integer_ord` domain carries only an `ore` (`ob`) index and no `hm`, so
  // `eql_v3.eq(integer_ord, operand)` internally compares `ord_term` — i.e.
  // equality answered through ORE. This proves that resolves the exact row
  // against real Postgres with a full operand (no `encryptQuery` term).
  it('selects the exact row for equality-via-ORE on an integer_ord column', async () => {
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
          ${sql.json(ageCt)}::public.integer_ord,
          ${sql.json(nick)}::public.text_eq,
          ${sql.json(act)}::public.boolean,
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

    // Full operand for 37; `eql_v3.eq(integer_ord, operand)` compares `ord_term`,
    // so this is equality answered via ORE.
    const equalityTerm = await encryptOperand(37, {
      table: typedTable,
      column: typedTable.age,
    })

    const matched = await sql<{ id: number }[]>`
      SELECT id
      FROM protect_ci_v3_typed_domains
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.eq(age, ${sql.json(equalityTerm)}::jsonb)
      ORDER BY id
    `
    // Exactly the age=37 row — not the 30 or 42 rows.
    expect(matched.map((row) => row.id)).toEqual([ids.thirtySeven])
    expect(matched.map((row) => row.id)).not.toContain(ids.thirty)
    expect(matched.map((row) => row.id)).not.toContain(ids.fortyTwo)

    // A non-matching value selects nothing.
    const missTerm = await encryptOperand(99, {
      table: typedTable,
      column: typedTable.age,
    })
    const none = await sql<{ id: number }[]>`
      SELECT id
      FROM protect_ci_v3_typed_domains
      WHERE test_run_id = ${TEST_RUN_ID}
        AND eql_v3.eq(age, ${sql.json(missTerm)}::jsonb)
    `
    expect(none).toHaveLength(0)
  }, 30000)
})
