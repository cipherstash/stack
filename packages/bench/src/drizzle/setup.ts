import { type EncryptionClientFor, EncryptionV3 } from '@cipherstash/stack/v3'
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

/**
 * A seed row, keyed by the Drizzle table's **JS property** names.
 *
 * That is what model encryption matches on: `extractEncryptionSchema` keys the
 * encrypted-table column map by property (`encText`), not by DB column name
 * (`enc_text`). A row keyed by DB name matches nothing — `bulkEncryptModels`
 * returns it untouched, with no failure, and the plaintext then goes into an
 * `eql_v3_*` column (#772 review, finding 12).
 *
 * HAND-WRITTEN — it cannot be derived from `benchTable` without getting weaker,
 * so `__unit__/seed-keys.test.ts` is the real drift guard, not the type.
 * Drizzle's `InferInsertModel` describes the ENCRYPTED column (the custom type's
 * `data` is the EQL envelope, not the plaintext) and degrades these three to
 * optional `any`. Deriving from `encryptionBenchTable` is no better:
 * `extractEncryptionSchema` returns the widened `AnyV3Table`, whose column map
 * is an index signature — a type that admits `encTxt: 'x'` and `encText: 12345`
 * alike, both of which the literal below rejects.
 *
 * Update it by hand when `benchTable` changes; the unit test will tell you.
 */
export type BenchPlaintextRow = {
  encText: string
  encInt: number
  encJsonb: { idx: number; group: number }
}

/** The typed EQL v3 client this bench drives. */
export type BenchEncryptionClient = EncryptionClientFor<
  readonly [typeof encryptionBenchTable]
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

  const encryptionClient = await EncryptionV3({
    schemas: [encryptionBenchTable],
  })

  return { pgClient, pool, db, encryptionClient }
}

export async function teardownBench(h: BenchHandle): Promise<void> {
  await h.pgClient.end()
  await h.pool.end()
}
