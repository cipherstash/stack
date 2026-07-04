import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type postgres from 'postgres'

const EQL_V3_ADVISORY_LOCK_ID = 3_733_003

const helperDir = dirname(fileURLToPath(import.meta.url))
// The upstream `eql-3.0.0-alpha.2` release artifact (cipherstash-encrypt.sql
// from cipherstash/encrypt-query-language), vendored byte-for-byte.
const eqlV3SqlPath = resolve(
  helperDir,
  '../fixtures/eql-v3/cipherstash-encrypt-v3.sql',
)
// The CLI-vendored Supabase variant (opclass chunks stripped by
// packages/cli/scripts/build-eql-v3-sql.mjs from the fixture above; CI keeps
// the two in sync). Upstream ships no Supabase variant for v3 yet, so it is
// still derived locally. Reading the shipped artifact instead of re-stripping
// here means the live Supabase suite installs exactly what
// `stash eql install --eql-version 3 --supabase` installs.
const eqlV3SupabaseSqlPath = resolve(
  helperDir,
  '../../../cli/src/sql/cipherstash-encrypt-v3-supabase.sql',
)

/**
 * The `eql_v3` + `eql_v3_internal` grants for the Supabase roles. Mirrors the
 * CLI's `supabasePermissionsSql('eql_v3')` (packages/cli/src/installer) —
 * inlined rather than imported because the stack package cannot resolve the
 * cli package's dependency graph (pg) from its test context.
 *
 * eql_v3_internal needs the same grants: the eql_v3 operators/domain CHECKs
 * call into SECURITY INVOKER functions and composite types there (SEM
 * index-term internals split out in eql-3.0.0-alpha.2), so without
 * USAGE/EXECUTE on eql_v3_internal every anon/authenticated encrypted query
 * fails 42501. Note: Supabase "Exposed schemas" must remain eql_v3 ONLY —
 * granting on eql_v3_internal does not (and must not) expose it via PostgREST.
 */
const EQL_V3_SUPABASE_GRANTS = `
  GRANT USAGE ON SCHEMA eql_v3 TO anon, authenticated, service_role;
  GRANT SELECT ON ALL TABLES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
  GRANT EXECUTE ON ALL ROUTINES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
  GRANT USAGE ON ALL SEQUENCES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT SELECT ON TABLES TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT USAGE ON SEQUENCES TO anon, authenticated, service_role;
  GRANT USAGE ON SCHEMA eql_v3_internal TO anon, authenticated, service_role;
  GRANT SELECT ON ALL TABLES IN SCHEMA eql_v3_internal TO anon, authenticated, service_role;
  GRANT EXECUTE ON ALL ROUTINES IN SCHEMA eql_v3_internal TO anon, authenticated, service_role;
  GRANT USAGE ON ALL SEQUENCES IN SCHEMA eql_v3_internal TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3_internal GRANT SELECT ON TABLES TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3_internal GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3_internal GRANT USAGE ON SEQUENCES TO anon, authenticated, service_role;
`

/**
 * Generation-aware install sentinel. `to_regtype('eql_v3.text_search')` alone
 * is NOT enough: text_search exists in both the pre-alpha.2 snapshot and the
 * current bundle, so a stale old-generation install would be silently reused.
 * The eql_v3_internal schema and the SQL-standard-renamed eql_v3.timestamp
 * domain only exist in the eql-3.0.0-alpha.2 generation, so requiring them
 * distinguishes current from stale.
 */
async function hasCurrentGenerationEqlV3(sql: postgres.Sql): Promise<boolean> {
  const [row] = await sql<{ installed: boolean }[]>`
    SELECT
      to_regtype('eql_v3.text_search') IS NOT NULL
      AND to_regtype('eql_v3.timestamp') IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v3_internal'
      ) AS installed
  `
  return row?.installed ?? false
}

/**
 * Install the vendored EQL v3 SQL bundle (eql-3.0.0-alpha.2) only when the
 * target database does not already have a current-generation install.
 *
 * The bundle starts with DROP SCHEMA IF EXISTS eql_v3 CASCADE (and drops
 * eql_v3_internal too), so callers must never run it unconditionally against
 * a shared test database.
 *
 * Pass `supabase: true` when targeting a Supabase database: the operator
 * class/family chunks are stripped (they need superuser) and the `eql_v3` and
 * `eql_v3_internal` schemas are granted to the Supabase roles, mirroring the
 * CLI's `--eql-version 3 --supabase` install.
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
      if (await hasCurrentGenerationEqlV3(reserved)) return

      // Reaching here means either nothing is installed, or a STALE
      // previous-generation install is present (eql_v3 exists — e.g.
      // eql_v3.text_search resolves — but the eql_v3_internal schema /
      // renamed domains are absent). Either way, re-run the bundle: it opens
      // with DROP SCHEMA IF EXISTS eql_v3 CASCADE and DROP SCHEMA IF EXISTS
      // eql_v3_internal CASCADE, so the stale install is replaced wholesale.
      // Belt-and-braces: drop eql_v3_internal explicitly first so the
      // reinstall stays idempotent even if a future bundle stops dropping it.
      await reserved`DROP SCHEMA IF EXISTS eql_v3_internal CASCADE`

      const eqlV3Sql = await readFile(
        options?.supabase ? eqlV3SupabaseSqlPath : eqlV3SqlPath,
        'utf8',
      )
      await reserved.unsafe(eqlV3Sql)

      if (options?.supabase) {
        // The Supabase roles don't own the schemas; without these grants every
        // encrypted query fails 42501 over PostgREST.
        await reserved.unsafe(EQL_V3_SUPABASE_GRANTS)
      }

      if (!(await hasCurrentGenerationEqlV3(reserved))) {
        throw new Error(
          'EQL v3 installation did not create the current-generation eql_v3 surface (eql_v3.text_search, eql_v3.timestamp, eql_v3_internal)',
        )
      }
    } finally {
      await reserved`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
    }
  } finally {
    reserved.release()
  }
}

/**
 * Version-handshake guard for the live suites: assert that a payload the
 * client just produced is a v:3-wire envelope matching the installed bundle's
 * domain CHECK pins (`VALUE->>'v' = '3'`, eql-3.0.0-alpha.2). A mismatch means
 * generation skew — a stale protect-ffi pin, missing `eqlVersion: 3` wiring,
 * or a stale vendored bundle — exactly the drift class that previously went
 * unnoticed (PR #547 originally wrote v2-wire data against v:2 CHECK pins).
 * Fail loudly and name the skew instead of letting inserts fail with an
 * opaque 23514 (or, worse, a mismatched bundle silently accept them).
 */
export function assertV3WireEnvelope(payload: unknown, context: string): void {
  const v =
    typeof payload === 'object' && payload !== null
      ? (payload as Record<string, unknown>).v
      : undefined
  if (v !== 3) {
    throw new Error(
      `EQL generation skew (${context}): client emitted an envelope with v=${JSON.stringify(v)} but the installed eql_v3 bundle (eql-3.0.0-alpha.2) pins v='3'. ` +
        'Check the @cipherstash/protect-ffi version (needs >= 0.27.0), the eqlVersion wiring (EncryptionV3 / Encryption auto-detection), and the vendored bundle generation.',
    )
  }
}
