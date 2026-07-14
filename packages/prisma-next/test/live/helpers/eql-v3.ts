/**
 * Idempotent, concurrency-safe EQL v3 install for the live suites.
 *
 * The install SQL comes from `src/migration/eql-bundle-v3.ts` — the
 * SAME `@cipherstash/eql/sql` `readInstallSql()` source the shipped v3
 * baseline migration bakes into its `ops.json` — so installing here
 * exercises the exact bytes a customer's migration applies (the
 * `migration-apply-live-pg` suite pins that byte-identity).
 *
 * Mirrors the stack's historical `installEqlV3IfNeeded` helper: a
 * session advisory lock serialises concurrent vitest workers (every
 * live suite installs in its `beforeAll`), and `eql_v3.version()` is
 * the staleness probe — reinstall only when the installed version
 * differs from the pinned release manifest.
 */

import type postgres from 'postgres'
import {
  readInstallSql,
  releaseManifest,
} from '../../../src/migration/eql-bundle-v3'

const EQL_V3_ADVISORY_LOCK_ID = 3_733_003

async function readEqlV3Version(
  sql: postgres.Sql | postgres.ReservedSql,
): Promise<string | null> {
  const [probe] = await sql<
    { present: boolean }[]
  >`SELECT to_regprocedure('eql_v3.version()') IS NOT NULL AS present`
  if (!probe?.present) return null
  const [row] = await sql<
    { version: string }[]
  >`SELECT eql_v3.version() AS version`
  return row?.version ?? null
}

export async function installEqlV3IfNeeded(sql: postgres.Sql): Promise<void> {
  // Advisory locks are session-scoped: reserve one physical connection
  // so lock and unlock land on the same session even though `postgres`
  // pools.
  const reserved = await sql.reserve()
  try {
    await reserved`SELECT pg_advisory_lock(${EQL_V3_ADVISORY_LOCK_ID})`
    try {
      if ((await readEqlV3Version(reserved)) === releaseManifest.eqlVersion) {
        return
      }
      await reserved.unsafe(readInstallSql())
      const installed = await readEqlV3Version(reserved)
      if (installed !== releaseManifest.eqlVersion) {
        throw new Error(
          `EQL v3 installation did not yield ${releaseManifest.eqlVersion}, got ${installed ?? 'none'}`,
        )
      }
    } finally {
      await reserved`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
    }
  } finally {
    reserved.release()
  }
}
