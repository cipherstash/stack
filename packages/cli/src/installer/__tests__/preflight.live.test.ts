/**
 * Live-Postgres coverage for `EQLInstaller.preflight()`.
 *
 * The unit tests feed the preflight a faked row, so they cannot prove the one
 * thing this file does: that `PREFLIGHT_SQL` is valid SQL against a real
 * server, in BOTH membership arms. The hazard is specific: `pg_has_role`
 * raises `role "postgres" does not exist` rather than returning false, so the
 * `CASE` guard is load-bearing — and the compose database (`POSTGRES_USER=
 * cipherstash`) bootstraps with no `postgres` role, which makes it the
 * fixture for the guarded arm.
 *
 * Gated on STASH_TEST_DATABASE_URL so the default `pnpm test` stays green
 * without a database. Locally:
 *
 *   docker compose -f local/docker-compose.postgres.yml up -d --wait
 *   export STASH_TEST_DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash
 */

import { afterAll, describe, expect, it } from 'vitest'

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

/** Unique per-run so a crashed previous run can't collide. */
const MEMBER_ROLE = `stash_preflight_member_${process.pid}`
const MEMBER_PASSWORD = 'stash-preflight-test'

async function adminQuery<T = unknown>(sql: string): Promise<T[]> {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: DATABASE_URL })
  await client.connect()
  try {
    const result = await client.query(sql)
    return result.rows as T[]
  } finally {
    await client.end().catch(() => undefined)
  }
}

async function postgresRoleExists(): Promise<boolean> {
  const rows = await adminQuery<{ n: number }>(
    "SELECT count(*)::int AS n FROM pg_roles WHERE rolname = 'postgres'",
  )
  return rows[0]?.n === 1
}

function urlAs(user: string, password: string): string {
  const url = new URL(DATABASE_URL as string)
  url.username = user
  url.password = password
  return url.toString()
}

describeLive('EQLInstaller.preflight — live Postgres', () => {
  afterAll(async () => {
    await adminQuery(`DROP ROLE IF EXISTS ${MEMBER_ROLE}`).catch(
      () => undefined,
    )
    // The `postgres` role is deliberately left behind: the guarded-grants
    // live suite shares it in the same run, and the compose database is
    // ephemeral (no volume), so dropping it here would only create races.
  })

  it('runs the real preflight query, guarding pg_has_role against a missing postgres role', async () => {
    const { EQLInstaller } = await import('../index.js')
    const installer = new EQLInstaller({
      databaseUrl: DATABASE_URL as string,
    })
    // The assertion that matters is that this does not throw: an unguarded
    // pg_has_role('postgres') raises when the role is absent. The sibling
    // guarded-grants suite may create the role concurrently, so sample
    // existence on both sides of the probe and only pin the null arm when it
    // was absent throughout.
    const existedBefore = await postgresRoleExists()
    const result = await installer.preflight()
    expect(result.currentUser).toBe('cipherstash')
    expect(result.isSuperuser).toBe(true)
    expect(result.ok).toBe(true)
    // The pgcrypto-placement and schema-ownership probes must be answers, not
    // query failures, whatever state the shared database is in.
    if (result.pgcryptoInstalled) {
      expect(typeof result.pgcryptoSchema).toBe('string')
    } else {
      expect(result.pgcryptoSchema).toBeNull()
    }
    if (result.eqlV3SchemaPresent) {
      // A superuser can always drop.
      expect(result.canDropEqlV3Schema).toBe(true)
    } else {
      expect(result.canDropEqlV3Schema).toBeNull()
    }
    const existedAfter = await postgresRoleExists()
    if (existedBefore) {
      // A superuser is a member of every role.
      expect(result.memberOfPostgres).toBe(true)
    } else if (!existedAfter) {
      expect(result.memberOfPostgres).toBeNull()
    }
    // Role appeared mid-probe (parallel suite): either arm is legitimate.
  })

  it('reports membership truthfully for member and non-member roles', async () => {
    const { EQLInstaller } = await import('../index.js')
    await adminQuery(
      'DO $$ BEGIN CREATE ROLE postgres; EXCEPTION WHEN duplicate_object THEN NULL; END $$',
    )
    await adminQuery(
      `CREATE ROLE ${MEMBER_ROLE} LOGIN PASSWORD '${MEMBER_PASSWORD}'`,
    )

    // A superuser is a member of every role.
    const asSuperuser = await new EQLInstaller({
      databaseUrl: DATABASE_URL as string,
    }).preflight()
    expect(asSuperuser.memberOfPostgres).toBe(true)

    // A plain login role is not.
    const asOutsider = await new EQLInstaller({
      databaseUrl: urlAs(MEMBER_ROLE, MEMBER_PASSWORD),
    }).preflight()
    expect(asOutsider.currentUser).toBe(MEMBER_ROLE)
    expect(asOutsider.isSuperuser).toBe(false)
    expect(asOutsider.memberOfPostgres).toBe(false)

    // ...until it is granted membership.
    await adminQuery(`GRANT postgres TO ${MEMBER_ROLE}`)
    const asMember = await new EQLInstaller({
      databaseUrl: urlAs(MEMBER_ROLE, MEMBER_PASSWORD),
    }).preflight()
    expect(asMember.memberOfPostgres).toBe(true)
  })

  /**
   * The ORE probe (#891) attempts `CREATE OPERATOR FAMILY` and rolls it back.
   * Only a live server can prove the two things that matter: that the
   * privilege gate answers `false` for an unprivileged role rather than
   * throwing, and that the rollback leaves nothing behind — the claim that
   * preflight is read-only.
   */
  it('probes operator-class creation truthfully, and leaves nothing behind', async () => {
    const { EQLInstaller } = await import('../index.js')
    await adminQuery(
      `DO $$ BEGIN CREATE ROLE ${MEMBER_ROLE} LOGIN PASSWORD '${MEMBER_PASSWORD}';
         EXCEPTION WHEN duplicate_object THEN NULL; END $$`,
    )

    const asSuperuser = await new EQLInstaller({
      databaseUrl: DATABASE_URL as string,
    }).preflight()
    expect(asSuperuser.canCreateOperatorClass).toBe(true)

    // A plain login role cannot: `CREATE OPERATOR FAMILY` is superuser-gated,
    // and the 42501 it raises is the answer, not a probe failure.
    const asOutsider = await new EQLInstaller({
      databaseUrl: urlAs(MEMBER_ROLE, MEMBER_PASSWORD),
    }).preflight()
    expect(asOutsider.isSuperuser).toBe(false)
    expect(asOutsider.canCreateOperatorClass).toBe(false)

    // The successful arm rolled back: no operator family survives. This is
    // what keeps `eql preflight` honest about being read-only.
    const leftovers = await adminQuery<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_catalog.pg_opfamily
        WHERE opfname = 'stash_preflight_opclass_probe'`,
    )
    expect(leftovers[0]?.n).toBe(0)
  })
})
