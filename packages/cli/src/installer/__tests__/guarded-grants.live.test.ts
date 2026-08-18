/**
 * Live proof that `SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3` — the
 * owner-scoped grants as shipped inside generated migration files — is valid
 * plpgsql and does what the guard promises in BOTH membership arms:
 *
 * - run by a role that is NOT a member of `postgres`, it succeeds silently
 *   (the unguarded form fails with `permission denied to change default
 *   privileges` and, in a migration, rolls back the whole file — the exact
 *   Lovable failure);
 * - run by a member, it actually records the default-privilege rules.
 *
 * A unit test cannot see either: `ALTER DEFAULT PRIVILEGES` inside a DO block
 * only proves itself against a real server.
 *
 * Gated on STASH_TEST_DATABASE_URL like the other live suites. The test is
 * self-sufficient on a fresh database: it creates the Supabase roles, the two
 * EQL schema names (bare — grants only need them to exist), and its own
 * postgres/member/outsider roles, and reverses the default-privilege rules it
 * created.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3 } from '../grants.js'

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

const OUTSIDER = `stash_guard_outsider_${process.pid}`
const MEMBER = `stash_guard_member_${process.pid}`
const PASSWORD = 'stash-guard-test'

async function query<T = unknown>(sql: string, url?: string): Promise<T[]> {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: url ?? DATABASE_URL })
  await client.connect()
  try {
    const result = await client.query(sql)
    return result.rows as T[]
  } finally {
    await client.end().catch(() => undefined)
  }
}

function urlAs(user: string): string {
  const url = new URL(DATABASE_URL as string)
  url.username = user
  url.password = PASSWORD
  return url.toString()
}

async function defaultAclCount(): Promise<number> {
  const rows = await query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_default_acl d
      JOIN pg_namespace n ON n.oid = d.defaclnamespace
      JOIN pg_roles r ON r.oid = d.defaclrole
     WHERE r.rolname = 'postgres' AND n.nspname IN ('eql_v3', 'eql_v3_internal')`,
  )
  return rows[0]?.n ?? 0
}

describeLive('guarded owner-scoped grants — live Postgres', () => {
  beforeAll(async () => {
    for (const role of ['anon', 'authenticated', 'service_role']) {
      await query(
        `DO $$ BEGIN CREATE ROLE ${role}; EXCEPTION WHEN duplicate_object THEN NULL; END $$`,
      )
    }
    await query('CREATE SCHEMA IF NOT EXISTS eql_v3')
    await query('CREATE SCHEMA IF NOT EXISTS eql_v3_internal')
    // Race-safe against the preflight live suite creating it concurrently;
    // left behind afterwards for the same reason (the database is ephemeral).
    await query(
      'DO $$ BEGIN CREATE ROLE postgres; EXCEPTION WHEN duplicate_object THEN NULL; END $$',
    )
    await query(`CREATE ROLE ${OUTSIDER} LOGIN PASSWORD '${PASSWORD}'`)
    await query(`CREATE ROLE ${MEMBER} LOGIN PASSWORD '${PASSWORD}'`)
    await query(`GRANT postgres TO ${MEMBER}`)
    // The member must be able to run the DO block's ALTER statements, which
    // act on role `postgres` in these schemas — schema USAGE is enough for
    // the block itself to execute.
    await query(
      `GRANT USAGE, CREATE ON SCHEMA eql_v3, eql_v3_internal TO ${OUTSIDER}, ${MEMBER}`,
    )
  })

  afterAll(async () => {
    // Reverse whatever the member arm recorded, then the fixture roles.
    await query(
      `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 REVOKE SELECT ON TABLES FROM anon, authenticated, service_role;
       ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 REVOKE EXECUTE ON ROUTINES FROM anon, authenticated, service_role;
       ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 REVOKE USAGE ON SEQUENCES FROM anon, authenticated, service_role;
       ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3_internal REVOKE EXECUTE ON ROUTINES FROM anon, authenticated, service_role;`,
    ).catch(() => undefined)
    await query(
      `REVOKE USAGE, CREATE ON SCHEMA eql_v3, eql_v3_internal FROM ${OUTSIDER}, ${MEMBER}`,
    ).catch(() => undefined)
    await query(`DROP ROLE IF EXISTS ${OUTSIDER}`).catch(() => undefined)
    await query(`DROP ROLE IF EXISTS ${MEMBER}`).catch(() => undefined)
  })

  it('succeeds silently for a role that is not a member of postgres', async () => {
    const before = await defaultAclCount()
    await expect(
      query(SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3, urlAs(OUTSIDER)),
    ).resolves.toBeDefined()
    // Guard skipped the statements: nothing recorded.
    expect(await defaultAclCount()).toBe(before)
  })

  it('records the default-privilege rules when run by a member of postgres', async () => {
    const before = await defaultAclCount()
    await query(SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3, urlAs(MEMBER))
    expect(await defaultAclCount()).toBeGreaterThan(before)
  })
})
