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
// The CLI-vendored Supabase variant (opclass chunks stripped by
// packages/cli/scripts/build-eql-v3-sql.mjs from the fixture above; CI keeps
// the two in sync). Reading the shipped artifact instead of re-stripping here
// means the live Supabase suite installs exactly what
// `stash eql install --eql-version 3 --supabase` installs.
const eqlV3SupabaseSqlPath = resolve(
  helperDir,
  '../../../cli/src/sql/cipherstash-encrypt-v3-supabase.sql',
)

/**
 * The `eql_v3` grants for the Supabase roles. Mirrors the CLI's
 * `SUPABASE_PERMISSIONS_SQL_V3` (`supabasePermissionsSql('eql_v3')` in
 * packages/cli/src/installer/index.ts) — inlined rather than imported because
 * the stack package cannot resolve the cli package's dependency graph (pg)
 * from its test context.
 */
const EQL_V3_SUPABASE_GRANTS = `
  GRANT USAGE ON SCHEMA eql_v3 TO anon, authenticated, service_role;
  GRANT SELECT ON ALL TABLES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
  GRANT EXECUTE ON ALL ROUTINES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
  GRANT USAGE ON ALL SEQUENCES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT SELECT ON TABLES TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT USAGE ON SEQUENCES TO anon, authenticated, service_role;
`

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

      const eqlV3Sql = await readFile(
        options?.supabase ? eqlV3SupabaseSqlPath : eqlV3SqlPath,
        'utf8',
      )
      await reserved.unsafe(eqlV3Sql)

      if (options?.supabase) {
        // The Supabase roles don't own the schema; without these grants every
        // encrypted query fails 42501 over PostgREST.
        await reserved.unsafe(EQL_V3_SUPABASE_GRANTS)
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
