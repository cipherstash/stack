import { Encryption } from '@cipherstash/stack'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import {
  encryptedType,
  extractEncryptionSchema,
} from '@cipherstash/stack-drizzle'
import { drizzle } from 'drizzle-orm/node-postgres'
import { pgTable, serial } from 'drizzle-orm/pg-core'
import pg from 'pg'
import { getDatabaseUrl } from '../harness/db.js'

/**
 * Drizzle schema for the bench table. Mirrors `sql/schema.sql`.
 *
 * `id` is `serial`; the encrypted columns are `eql_v2_encrypted` composites
 * driven by `@cipherstash/stack-drizzle`'s `encryptedType`.
 *
 * Index config flags (`equality`, `freeTextSearch`, `orderAndRange`,
 * `searchableJson`) are deliberately all on — the bench needs to exercise
 * every query family that lands on the table.
 */
export const benchTable = pgTable('bench', {
  id: serial('id').primaryKey(),
  encText: encryptedType<string>('enc_text', {
    equality: true,
    freeTextSearch: true,
    orderAndRange: true,
  }),
  encInt: encryptedType<number>('enc_int', {
    dataType: 'number',
    equality: true,
    orderAndRange: true,
  }),
  encJsonb: encryptedType<{ idx: number; group: number }>('enc_jsonb', {
    dataType: 'json',
    searchableJson: true,
  }),
})

/**
 * Encryption schema for the stack `Encryption()` client. Derived from the
 * Drizzle table above so the two can't drift apart.
 */
export const encryptionBenchTable = extractEncryptionSchema(benchTable)

export type BenchPlaintextRow = {
  enc_text: string
  enc_int: number
  enc_jsonb: { idx: number; group: number }
}

export type BenchHandle = {
  pgClient: pg.Client
  pool: pg.Pool
  db: ReturnType<typeof drizzle>
  encryptionClient: EncryptionClient
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

  const encryptionClient = await Encryption({ schemas: [encryptionBenchTable] })

  return { pgClient, pool, db, encryptionClient }
}

export async function teardownBench(h: BenchHandle): Promise<void> {
  await h.pgClient.end()
  await h.pool.end()
}
