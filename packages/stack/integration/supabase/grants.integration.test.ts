/**
 * Live proof that the shipped Supabase v3 grants let `anon` actually run the
 * queries the v3 adapter emits.
 *
 * ## What went wrong
 * `supabasePermissionsSql` granted exactly one schema, `eql_v3`. But the public
 * entry points the query path calls — `eql_v3.eq_term`, `ord_term`,
 * `match_term` — are SECURITY INVOKER and qualify `eql_v3_internal.*` by name in
 * their bodies. Postgres resolves those names with the CALLER's privileges and
 * checks schema USAGE at name resolution, so `anon` got
 * `permission denied for schema eql_v3_internal` on EVERY encrypted filter:
 * `=` (eq_term), `>=` (ord_term) and `@>`/`cs` (match_term) alike.
 *
 * `packages/stack/__tests__/supabase-v3-builder.test.ts` cannot see this — it
 * records wire strings against a mock. Only a real Postgres can.
 *
 * ## Why the grants SQL is imported from `stash`
 * Via `../../cli/src/installer/grants` — an import-free module — rather than a
 * package dependency: `stash` already depends on `@cipherstash/stack`, so a
 * dependency the other way would be a cycle. Asserting against the EXACT string
 * the CLI installs (and embeds into the generated Supabase migration) is the
 * whole point; a local copy would drift and this suite would prove nothing.
 *
 * ## Why no CipherStash credentials
 * The probe never needs ciphertext. `eql_v3_internal.ore_block_256('{}')` fails
 * on DATA for a caller that can resolve the schema, and on PERMISSION for one
 * that cannot. Those two errors are what separate a working `anon` from a
 * broken one, and neither requires a valid envelope — so this runs on the
 * `DATABASE_URL`-only gate, alongside `supabase-v3-introspect-pg`.
 */

import { databaseUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  SUPABASE_PERMISSIONS_SQL_V3,
  supabaseInternalPermissionsSql,
} from '../../../cli/src/installer/grants'

const sql = postgres(databaseUrl(), { prepare: false })

const INTERNAL_SCHEMA = 'eql_v3_internal'

/** The roles `SUPABASE_PERMISSIONS_SQL_V3` names. `postgres` is named too, by
 * the `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` lines — a plain Postgres
 * image has none of them. */
const REQUIRED_ROLES = ['postgres', 'anon', 'authenticated', 'service_role']

/**
 * The probe: resolvable-but-invalid input.
 *
 * - caller CAN reach the schema → PL/pgSQL raises `Expected an ore index (ob)…`
 * - caller CANNOT              → the parser raises `permission denied for schema`
 *
 * The distinction is the entire test, and it needs no encryption client.
 */
const PROBE = `SELECT ${INTERNAL_SCHEMA}.ore_block_256('{}'::jsonb)`
const DATA_ERROR = /Expected an ore index/i
const PERMISSION_ERROR = /permission denied for schema eql_v3_internal/i

/** Run `PROBE` as `anon`, returning the error message Postgres raised. */
async function probeAsAnon(): Promise<string> {
  const reserved = await sql.reserve()
  try {
    await reserved.unsafe('SET ROLE anon')
    await reserved.unsafe(PROBE)
    return '<no error>'
  } catch (error) {
    return (error as Error).message
  } finally {
    await reserved.unsafe('RESET ROLE').catch(() => {})
    reserved.release()
  }
}

beforeAll(async () => {
  // EQL v3 (and its `--supabase` grants) is installed once per run by
  // `global-setup.ts`; this suite then revokes and re-applies the grant SQL in
  // isolation to prove that SQL, so it needs the schema to already exist.

  // `CREATE ROLE IF NOT EXISTS` does not exist; a shared CI database may
  // already carry these from an earlier run.
  for (const role of REQUIRED_ROLES) {
    await sql.unsafe(`
      DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN
          CREATE ROLE ${role} NOLOGIN;
        END IF;
      END $$;
    `)
  }

  // Start from no internal-schema access. GRANTs persist in the database, so on
  // a reused local database (or a rerun) the roles would still carry USAGE from
  // the previous run and this suite would pass without the SQL under test ever
  // granting anything. Revoking first makes the assertions depend on
  // `SUPABASE_PERMISSIONS_SQL_V3` rather than on accumulated state. Only these
  // three roles are touched; the owner every other live suite connects as is
  // unaffected.
  await sql.unsafe(
    `REVOKE ALL ON SCHEMA ${INTERNAL_SCHEMA} FROM anon, authenticated, service_role`,
  )

  // The SQL under test, executed exactly as the CLI installer executes it:
  // one multi-statement string.
  await sql.unsafe(SUPABASE_PERMISSIONS_SQL_V3)
}, 120_000)

afterAll(async () => {
  await sql.end()
})

describe('supabase v3 grants against real Postgres', () => {
  it('grants anon USAGE on eql_v3_internal', async () => {
    const [row] = await sql<{ usage: boolean }[]>`
      SELECT has_schema_privilege('anon', ${INTERNAL_SCHEMA}, 'USAGE') AS usage
    `
    expect(row.usage).toBe(true)
  })

  // The regression itself. Before the fix this raised
  // "permission denied for schema eql_v3_internal".
  it('lets anon resolve the internal schema the term extractors reach into', async () => {
    const message = await probeAsAnon()

    expect(message).not.toMatch(PERMISSION_ERROR)
    expect(message).toMatch(DATA_ERROR)
  })

  // Proves the assertion above is not vacuous: strip ONLY the internal-schema
  // grants and anon breaks; re-apply them and it recovers. Without this, a
  // future change that made `ore_block_256` fail early — or that dropped the
  // internal grants while some other GRANT happened to cover them — would leave
  // the test above passing for the wrong reason.
  it('breaks anon when the internal-schema grants are removed', async () => {
    await sql.unsafe(`REVOKE ALL ON SCHEMA ${INTERNAL_SCHEMA} FROM anon`)
    try {
      expect(await probeAsAnon()).toMatch(PERMISSION_ERROR)
    } finally {
      await sql.unsafe(supabaseInternalPermissionsSql(INTERNAL_SCHEMA))
    }

    expect(await probeAsAnon()).toMatch(DATA_ERROR)
  })

  // WHY the grant is needed. If EQL upstream ever makes these SECURITY DEFINER,
  // or stops qualifying the internal schema, the grant becomes unnecessary and
  // this suite should be revisited rather than silently kept alive.
  it('term extractors are SECURITY INVOKER and qualify eql_v3_internal', async () => {
    const rows = await sql<
      { proname: string; total: bigint; qualifies: bigint; invoker: boolean }[]
    >`
      SELECT p.proname,
             count(*) AS total,
             count(*) FILTER (WHERE p.prosrc LIKE '%eql_v3_internal.%') AS qualifies,
             bool_and(NOT p.prosecdef) AS invoker
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'eql_v3'
        AND p.proname IN ('eq_term', 'ord_term', 'match_term')
      GROUP BY p.proname
    `

    expect(rows.map((r) => r.proname).sort()).toEqual([
      'eq_term',
      'match_term',
      'ord_term',
    ])
    for (const row of rows) {
      expect(row.invoker).toBe(true)
      expect(Number(row.qualifies)).toBeGreaterThan(0)
    }
  })
})
