import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type postgres from 'postgres'

const EQL_V3_ADVISORY_LOCK_ID = 3_733_003

const helperDir = dirname(fileURLToPath(import.meta.url))
const eqlV3SqlPath = resolve(
  helperDir,
  '../fixtures/eql-v3/cipherstash-encrypt-v3.sql',
)

async function hasEqlV3TextSearch(sql: postgres.Sql): Promise<boolean> {
  const [row] = await sql<{ installed: boolean }[]>`
    SELECT to_regtype('eql_v3.text_search') IS NOT NULL AS installed
  `
  return row?.installed ?? false
}

/**
 * Install the generated EQL v3 SQL bundle only when the target database does
 * not already expose eql_v3.text_search.
 *
 * The bundle starts with DROP SCHEMA IF EXISTS eql_v3 CASCADE, so callers must
 * never run it unconditionally against a shared test database.
 */
export async function installEqlV3IfNeeded(sql: postgres.Sql): Promise<void> {
  await sql`SELECT pg_advisory_lock(${EQL_V3_ADVISORY_LOCK_ID})`

  try {
    if (await hasEqlV3TextSearch(sql)) return

    const eqlV3Sql = await readFile(eqlV3SqlPath, 'utf8')
    await sql.unsafe(eqlV3Sql)

    if (!(await hasEqlV3TextSearch(sql))) {
      throw new Error('EQL v3 installation did not create eql_v3.text_search')
    }
  } finally {
    await sql`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
  }
}
