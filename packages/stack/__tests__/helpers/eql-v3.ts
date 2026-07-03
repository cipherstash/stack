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

// The sentinel must be a type that exists ONLY in the currently vendored
// bundle, so a database still carrying an older EQL v3 install is detected as
// stale and reinstalled (the bundle's leading DROP SCHEMA … CASCADE replaces
// the old install wholesale). eql_v3.timestamp is new in the current bundle
// (the timestamptz → timestamp rename, encrypt-query-language@2e64ca73); the
// previous sentinel, eql_v3.text_search, exists in both generations and would
// leave a stale install in place.
async function hasCurrentEqlV3(sql: postgres.Sql): Promise<boolean> {
  const [row] = await sql<{ installed: boolean }[]>`
    SELECT to_regtype('eql_v3.timestamp') IS NOT NULL AS installed
  `
  return row?.installed ?? false
}

/**
 * Install the generated EQL v3 SQL bundle only when the target database does
 * not already expose the current bundle's sentinel type (see hasCurrentEqlV3).
 *
 * The bundle starts with DROP SCHEMA IF EXISTS eql_v3 CASCADE, so callers must
 * never run it unconditionally against a shared test database.
 */
export async function installEqlV3IfNeeded(sql: postgres.Sql): Promise<void> {
  // Advisory locks are session-scoped, so the whole check/install/unlock flow
  // must run on a single reserved connection. Issuing the lock/unlock via the
  // pool can land them on different pooled backends — allowing an install race
  // and unlocking a backend that never held the lock.
  const reserved = await sql.reserve()

  try {
    await reserved`SELECT pg_advisory_lock(${EQL_V3_ADVISORY_LOCK_ID})`

    try {
      if (await hasCurrentEqlV3(reserved)) return

      const eqlV3Sql = await readFile(eqlV3SqlPath, 'utf8')
      await reserved.unsafe(eqlV3Sql)

      if (!(await hasCurrentEqlV3(reserved))) {
        throw new Error('EQL v3 installation did not create eql_v3.timestamp')
      }
    } finally {
      await reserved`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
    }
  } finally {
    reserved.release()
  }
}
