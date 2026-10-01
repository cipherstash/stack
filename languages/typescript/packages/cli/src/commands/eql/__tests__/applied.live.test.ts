/**
 * Live-Postgres coverage for the applied-migration probe.
 *
 * Everything else about `eql repair` is tested against a faked `pg`, which is
 * right for the command's control flow but cannot check the one thing this
 * probe is: a real query against a real drizzle ledger. Under the fake, a typo
 * in the relation name, the column name, or the SQLSTATE set fails nothing —
 * and a wrong SQLSTATE set is the difference between "nothing is applied" and
 * "the check did not run", which is the fail-open this command exists to avoid.
 *
 * The ledger is created with drizzle's own DDL (`drizzle-orm@0.45.2`
 * `pg-core/dialect.js`, the `migrationTableCreate` in `migrate()`) rather than
 * by running `drizzle-kit migrate`: drizzle-kit is not a dependency of this
 * repo — the CLI shells out to the user's copy — so pulling it in to write four
 * rows would be a large commitment for little extra proof. What that leaves
 * unproven is drizzle's own `created_at = folderMillis` insert, which is pinned
 * by reading its source (`dialect.js:67`), not by this suite.
 *
 * Gated on STASH_TEST_DATABASE_URL so the default `pnpm test` stays green
 * without a database. Locally:
 *
 *   docker compose -f local/docker-compose.postgres.yml up -d --wait
 *   export STASH_TEST_DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash
 */

import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_MIGRATIONS_RELATION,
  LEDGER_ABSENT,
  latestAppliedMillis,
  NOTHING_APPLIED,
} from '../applied.js'

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

/** drizzle's own ledger DDL, copied from `pg-core/dialect.js` `migrate()`. */
const LEDGER_DDL = (schema: string, table: string) => `
  CREATE TABLE IF NOT EXISTS "${schema}"."${table}" (
    id SERIAL PRIMARY KEY,
    hash text NOT NULL,
    created_at bigint
  )
`

describeLive('latestAppliedMillis — live Postgres', () => {
  // Imported lazily for the same reason the probe does it: the module must not
  // pull in the driver on the offline path.
  async function withClient<T>(
    fn: (q: (sql: string) => Promise<void>) => Promise<T>,
  ): Promise<T> {
    const { default: pg } = await import('pg')
    const client = new pg.Client({ connectionString: DATABASE_URL })
    await client.connect()
    try {
      return await fn(async (sql: string) => {
        await client.query(sql)
      })
    } finally {
      await client.end().catch(() => undefined)
    }
  }

  async function resetLedger({
    schema,
    table,
    rows,
  }: {
    schema: string
    table: string
    rows: number[]
  }): Promise<void> {
    await withClient(async (q) => {
      await q(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`)
      await q(`CREATE SCHEMA "${schema}"`)
      await q(LEDGER_DDL(schema, table))
      for (const [i, created] of rows.entries()) {
        await q(
          `INSERT INTO "${schema}"."${table}" (hash, created_at) VALUES ('h${i}', ${created})`,
        )
      }
    })
  }

  beforeEach(async () => {
    await resetLedger({
      schema: 'drizzle',
      table: '__drizzle_migrations',
      rows: [],
    })
  })

  afterAll(async () => {
    await withClient(async (q) => {
      await q('DROP SCHEMA IF EXISTS "drizzle" CASCADE')
      await q('DROP SCHEMA IF EXISTS "audit" CASCADE')
    })
  })

  // The relation and column names, and that the query is valid SQL at all.
  it('reads the highest created_at from a real drizzle ledger', async () => {
    await resetLedger({
      schema: 'drizzle',
      table: '__drizzle_migrations',
      rows: [1_000, 3_000, 2_000],
    })

    await expect(latestAppliedMillis(DATABASE_URL as string)).resolves.toBe(
      3_000,
    )
  })

  /**
   * `created_at` is `bigint`, which node-postgres hands back as a STRING to
   * avoid a lossy conversion — the reason the probe calls Number() on it. A
   * real epoch-millis timestamp is past 2^31, so a value that survives as a
   * string but breaks under a 32-bit assumption is the one worth pinning.
   */
  it('converts a bigint created_at past 2^31 to a number', async () => {
    const when = 1_767_225_600_000 // 2026-01-01T00:00:00Z
    await resetLedger({
      schema: 'drizzle',
      table: '__drizzle_migrations',
      rows: [when],
    })

    const watermark = await latestAppliedMillis(DATABASE_URL as string)
    expect(watermark).toBe(when)
    expect(typeof watermark).toBe('number')
  })

  // `max()` over an empty table returns ONE row holding NULL, not zero rows.
  // The probe reads `rows[0]?.max_created_at` and treats null and undefined
  // alike, but only this test shows which one Postgres actually produces.
  it('reports an existing but empty ledger as NOTHING_APPLIED', async () => {
    await expect(latestAppliedMillis(DATABASE_URL as string)).resolves.toBe(
      NOTHING_APPLIED,
    )
  })

  /**
   * The SQLSTATE the LEDGER_ABSENT classification rests on. Getting it wrong
   * turns an absent ledger into a hard failure — or worse, some other error
   * into a silent "nothing applied". Not observable under a fake, which returns
   * whatever code the test author typed.
   *
   * Both cases below raise **42P01**. A SELECT against a schema-qualified
   * relation reports `relation "s.t" does not exist` whether it is the table or
   * the schema that is missing; `3F000` (invalid_schema_name) comes from
   * statements that name a schema directly, such as `SET search_path`, and this
   * query never produces it. Verified by mutation: dropping `3F000` from
   * NO_LEDGER leaves both of these green, dropping `42P01` fails both.
   */
  it('reports a missing table as LEDGER_ABSENT (42P01)', async () => {
    await withClient(async (q) => {
      await q('DROP TABLE IF EXISTS "drizzle"."__drizzle_migrations"')
    })

    await expect(latestAppliedMillis(DATABASE_URL as string)).resolves.toBe(
      LEDGER_ABSENT,
    )
  })

  it('reports a missing schema as LEDGER_ABSENT (also 42P01)', async () => {
    await withClient(async (q) => {
      await q('DROP SCHEMA IF EXISTS "drizzle" CASCADE')
    })

    await expect(latestAppliedMillis(DATABASE_URL as string)).resolves.toBe(
      LEDGER_ABSENT,
    )
  })

  // --migrations-table's whole purpose: the quoted relation must be SQL a real
  // Postgres accepts, schema-qualified and bare alike.
  it('reads a schema-qualified custom ledger', async () => {
    await resetLedger({
      schema: 'audit',
      table: 'applied_migrations',
      rows: [5_000],
    })

    await expect(
      latestAppliedMillis(DATABASE_URL as string, 'audit.applied_migrations'),
    ).resolves.toBe(5_000)
  })

  it('reads an unqualified custom ledger via search_path', async () => {
    await withClient(async (q) => {
      await q('DROP TABLE IF EXISTS public."my_migrations"')
      await q(LEDGER_DDL('public', 'my_migrations'))
      // Plain digits, not 7_000: underscore separators in numeric literals are
      // Postgres 16+, and nothing here needs to require that.
      await q(
        `INSERT INTO public."my_migrations" (hash, created_at) VALUES ('h', 7000)`,
      )
    })

    await expect(
      latestAppliedMillis(DATABASE_URL as string, 'my_migrations'),
    ).resolves.toBe(7_000)

    await withClient(async (q) => {
      await q('DROP TABLE IF EXISTS public."my_migrations"')
    })
  })

  /**
   * The case that makes the quoting load-bearing rather than cosmetic.
   * `isValidRelation` accepts mixed case, and Postgres folds an UNQUOTED
   * identifier to lower case — so a ledger actually created as "Audit" would be
   * looked up as `audit` and reported as absent, silently disabling the check.
   * Only quoting keeps it findable, and only a live database can show that:
   * against a fake, quoted and unquoted SQL are both just strings.
   */
  it('finds a mixed-case ledger, which only survives quoting', async () => {
    await resetLedger({
      schema: 'Audit',
      table: 'Applied_Migrations',
      rows: [11_000],
    })

    await expect(
      latestAppliedMillis(DATABASE_URL as string, 'Audit.Applied_Migrations'),
    ).resolves.toBe(11_000)

    await withClient(async (q) => {
      await q('DROP SCHEMA IF EXISTS "Audit" CASCADE')
    })
  })

  // A validated-but-wrong --migrations-table names a relation that does not
  // exist. It must classify as absent (and so warn) rather than throw — the
  // command reports a thrown probe as a hard failure.
  it('reports a validly-named but nonexistent ledger as LEDGER_ABSENT', async () => {
    await expect(
      latestAppliedMillis(DATABASE_URL as string, 'nope_not_here'),
    ).resolves.toBe(LEDGER_ABSENT)
  })

  // Guards the default the command relies on when --migrations-table is absent.
  it('defaults to drizzle.__drizzle_migrations', async () => {
    await resetLedger({
      schema: 'drizzle',
      table: '__drizzle_migrations',
      rows: [9_000],
    })

    await expect(
      latestAppliedMillis(DATABASE_URL as string, DEFAULT_MIGRATIONS_RELATION),
    ).resolves.toBe(9_000)
  })
})
