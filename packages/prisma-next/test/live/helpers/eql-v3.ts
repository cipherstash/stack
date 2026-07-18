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

import { readUninstallSql } from '@cipherstash/eql/sql'
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

/**
 * Reset to a clean pre-install state, under the same advisory lock as
 * the installer: run the release's own uninstall SQL (`DROP SCHEMA
 * eql_v3 / eql_v3_internal CASCADE`), removing `eql_v3.version()` so a
 * following {@link installEqlV3IfNeeded} MUST take the full install
 * path instead of short-circuiting on the version probe. The
 * `public.eql_v3_*` storage domains deliberately survive (the bundle
 * creates them idempotently and application tables depend on them), so
 * the other live suites' tables stay intact.
 */
export async function uninstallEqlV3(sql: postgres.Sql): Promise<void> {
  const reserved = await sql.reserve()
  try {
    await reserved`SELECT pg_advisory_lock(${EQL_V3_ADVISORY_LOCK_ID})`
    try {
      await reserved.unsafe(readUninstallSql())
      if ((await readEqlV3Version(reserved)) !== null) {
        throw new Error('EQL v3 uninstall left eql_v3.version() behind')
      }
    } finally {
      await reserved`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
    }
  } finally {
    reserved.release()
  }
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
