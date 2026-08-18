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

let createdPostgresRole = false

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
    if (createdPostgresRole) {
      await adminQuery('DROP ROLE IF EXISTS postgres').catch(() => undefined)
    }
  })

  it('runs the real preflight query, guarding pg_has_role against a missing postgres role', async () => {
    const { EQLInstaller } = await import('../index.js')
    const installer = new EQLInstaller({
      databaseUrl: DATABASE_URL as string,
    })
    // The assertion that matters is that this does not throw: an unguarded
    // pg_has_role('postgres') raises when the role is absent.
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
    if (await postgresRoleExists()) {
      // Image variant that ships a postgres role: a superuser is a member.
      expect(result.memberOfPostgres).toBe(true)
    } else {
      expect(result.memberOfPostgres).toBeNull()
    }
  })

  it('reports membership truthfully for member and non-member roles', async () => {
    const { EQLInstaller } = await import('../index.js')
    if (!(await postgresRoleExists())) {
      await adminQuery('CREATE ROLE postgres')
      createdPostgresRole = true
    }
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
})
