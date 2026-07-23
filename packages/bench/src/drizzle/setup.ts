import { EncryptionV3 } from '@cipherstash/stack/v3'
import { extractEncryptionSchema, types } from '@cipherstash/stack-drizzle'
import { drizzle } from 'drizzle-orm/node-postgres'
import { pgTable, serial } from 'drizzle-orm/pg-core'
import pg from 'pg'
import { getDatabaseUrl } from '../harness/db.js'

/**
 * Drizzle schema for the bench table. Mirrors `sql/schema.sql`.
 *
 * `id` is `serial`; the encrypted columns are concrete `eql_v3_*` Postgres
 * domains emitted by `@cipherstash/stack-drizzle`'s `types.*` factories.
 *
 * The domains are chosen to exercise every query family the bench lands on the
 * table: `TextSearch` (equality + free-text + order/range), `IntegerOrd`
 * (equality + order/range), and `Json` (encrypted-JSONB containment + selector).
 */
export const benchTable = pgTable('bench', {
  id: serial('id').primaryKey(),
  encText: types.TextSearch('enc_text'),
  encInt: types.IntegerOrd('enc_int'),
  encJsonb: types.Json('enc_jsonb'),
})

/**
 * Encryption schema for the `EncryptionV3()` client. Derived from the Drizzle
 * table above so the two can't drift apart.
 */
export const encryptionBenchTable = extractEncryptionSchema(benchTable)

export type BenchPlaintextRow = {
  enc_text: string
  enc_int: number
  enc_jsonb: { idx: number; group: number }
}

/**
 * Build the typed EQL v3 client this bench drives. Wrapped in a
 * single-signature helper because `EncryptionV3` is now overloaded (typed v3
 * vs. nominal) — `ReturnType<typeof EncryptionV3>` resolves to the *last*
 * (nominal) overload, so we infer the return type through this helper instead.
 */
function makeEncryptionClient() {
  return EncryptionV3({ schemas: [encryptionBenchTable] })
}

/** The typed EQL v3 client this bench drives. */
export type BenchEncryptionClient = Awaited<
  ReturnType<typeof makeEncryptionClient>
>

export type BenchHandle = {
  pgClient: pg.Client
  pool: pg.Pool
  db: ReturnType<typeof drizzle>
  encryptionClient: BenchEncryptionClient
}

/**
 * Spin up a single shared pg.Pool + Drizzle handle + Encryption client for
 * the bench. Reuses one connection for EXPLAIN (so prepared-statement state
 * is stable) and a pool for inserts.
 */
export async function buildBench(): Promise<BenchHandle> {
  const connectionString = getDatabaseUrl()
  const pool = new pg.Pool({ connectionString, max: 4 })
  const pgClient = new pg.Client({ connectionString })
  await pgClient.connect()

  const db = drizzle(pool)

  const encryptionClient = await makeEncryptionClient()

  return { pgClient, pool, db, encryptionClient }
}

export async function teardownBench(h: BenchHandle): Promise<void> {
  await h.pgClient.end()
  await h.pool.end()
}
