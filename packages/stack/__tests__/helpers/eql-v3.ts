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
 * Strip the two `CREATE OPERATOR CLASS`/`FAMILY` chunks from the v3 bundle.
 * They require superuser, which Supabase does not grant. Mirrors the upstream
 * build's `**\/*operator_class.sql` exclusion glob via the bundle's
 * `--! @file` markers (same logic as packages/cli/scripts/build-eql-v3-sql.mjs,
 * which vendors the stripped bundle for the CLI).
 */
function stripOperatorClassChunks(sql: string): string {
  const lines = sql.split('\n')
  const out: string[] = []
  let skipping = false

  for (const line of lines) {
    const marker = line.match(/^--! @file (.+)$/)
    if (marker) {
      skipping = /operator_class\.sql$/.test(marker[1])
    }
    if (!skipping) out.push(line)
  }

  const stripped = out.join('\n')
  if (/CREATE OPERATOR (CLASS|FAMILY)/.test(stripped)) {
    throw new Error(
      'Stripped EQL v3 bundle still contains CREATE OPERATOR CLASS/FAMILY statements',
    )
  }
  return stripped
}

/**
 * Install the generated EQL v3 SQL bundle only when the target database does
 * not already expose eql_v3.text_search.
 *
 * The bundle starts with DROP SCHEMA IF EXISTS eql_v3 CASCADE, so callers must
 * never run it unconditionally against a shared test database.
 *
 * Pass `supabase: true` when targeting a Supabase database: the operator
 * class/family chunks are stripped (they need superuser) and the `eql_v3`
 * schema is granted to the Supabase roles, mirroring the CLI's
 * `--eql-version 3 --supabase` install.
 */
export async function installEqlV3IfNeeded(
  sql: postgres.Sql,
  options?: { supabase?: boolean },
): Promise<void> {
  // Advisory locks are session-scoped, so the whole check/install/unlock flow
  // must run on a single reserved connection. Issuing the lock/unlock via the
  // pool can land them on different pooled backends — allowing an install race
  // and unlocking a backend that never held the lock.
  const reserved = await sql.reserve()

  try {
    await reserved`SELECT pg_advisory_lock(${EQL_V3_ADVISORY_LOCK_ID})`

    try {
      if (await hasEqlV3TextSearch(reserved)) return

      let eqlV3Sql = await readFile(eqlV3SqlPath, 'utf8')
      if (options?.supabase) {
        eqlV3Sql = stripOperatorClassChunks(eqlV3Sql)
      }
      await reserved.unsafe(eqlV3Sql)

      if (options?.supabase) {
        // Same grants the CLI applies (supabasePermissionsSql keyed to
        // eql_v3): the Supabase roles don't own the schema, and without these
        // every encrypted query fails 42501 over PostgREST.
        await reserved.unsafe(`
          GRANT USAGE ON SCHEMA eql_v3 TO anon, authenticated, service_role;
          GRANT SELECT ON ALL TABLES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
          GRANT EXECUTE ON ALL ROUTINES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
          GRANT USAGE ON ALL SEQUENCES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
          ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT SELECT ON TABLES TO anon, authenticated, service_role;
          ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
          ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT USAGE ON SEQUENCES TO anon, authenticated, service_role;
        `)
      }

      if (!(await hasEqlV3TextSearch(reserved))) {
        throw new Error('EQL v3 installation did not create eql_v3.text_search')
      }
    } finally {
      await reserved`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
    }
  } finally {
    reserved.release()
  }
}
