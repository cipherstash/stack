import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
import type postgres from 'postgres'

const EQL_V3_ADVISORY_LOCK_ID = 3_733_003

// Staleness is decided by asking the database which EQL release it is running
// and comparing that to the release the pinned @cipherstash/eql ships. Earlier
// revisions probed for a sentinel type (public.text_search, then
// public.timestamp) that was hand-picked to exist only in the newest bundle.
// Every such sentinel decays: the next bundle keeps the type, the check starts
// reporting "current" against a stale install, and the suite silently exercises
// the wrong SQL. eql_v3.version() carries the release identity itself, so this
// needs no maintenance when the pin moves.
//
// to_regprocedure() yields NULL instead of raising when the function is absent,
// so a database with no EQL v3 — or with a bundle predating eql_v3.version() —
// reads as stale and gets installed rather than erroring.
async function hasCurrentEqlV3(sql: postgres.Sql): Promise<boolean> {
  const [row] = await sql<{ version: string | null }[]>`
    SELECT CASE
      WHEN to_regprocedure('eql_v3.version()') IS NULL THEN NULL
      ELSE eql_v3.version()
    END AS version
  `
  return row?.version === releaseManifest.eqlVersion
}

/**
 * Install the EQL v3 SQL bundle shipped by @cipherstash/eql only when the
 * target database is not already running that exact release.
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

      // Sent as one multi-statement string: the bundle is ~43k lines and a
      // statement-at-a-time client would pay a round-trip per CREATE FUNCTION.
      await reserved.unsafe(readInstallSql())

      if (!(await hasCurrentEqlV3(reserved))) {
        const [row] = await reserved<{ version: string | null }[]>`
          SELECT CASE
            WHEN to_regprocedure('eql_v3.version()') IS NULL THEN NULL
            ELSE eql_v3.version()
          END AS version
        `
        throw new Error(
          `EQL v3 installation did not yield the expected release: wanted ${releaseManifest.eqlVersion}, got ${row?.version ?? 'no eql_v3.version()'}`,
        )
      }
    } finally {
      await reserved`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
    }
  } finally {
    reserved.release()
  }
}
