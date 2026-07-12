import { releaseManifest } from '@cipherstash/eql/sql'
import { databaseUrl, dbVariant, pgrestUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { afterAll, expect, it } from 'vitest'

/**
 * Proves the harness itself, so a failure in the adapter suites is never
 * ambiguous between "the adapter is broken" and "the database was never set up".
 *
 * `globalSetup` has already run `stash eql install --eql-version 3` against the
 * configured database by the time this file executes. Nothing here is skippable:
 * an unconfigured run throws in `globalSetup`, before any test is collected.
 */
const sql = postgres(databaseUrl(), { prepare: false })

afterAll(async () => {
  await sql.end()
})

it('installed the pinned EQL v3 release through the real CLI', async () => {
  const [row] = await sql<
    { version: string }[]
  >`SELECT eql_v3.version() AS version`

  expect(row?.version).toBe(releaseManifest.eqlVersion)
})

it('installed the concrete public.eql_v3_* domains', async () => {
  const [row] = await sql<{ count: string }[]>`
    SELECT count(*)::text AS count
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'public' AND t.typname LIKE 'eql_v3\\_%'
  `

  // The SDK models 41 of them; the bundle ships more (json, jsonb_entry, the
  // `*_ord_ope` twins). Assert the floor, not the exact count, so a bundle that
  // adds a domain does not fail a test that is really about "the install ran".
  expect(Number(row?.count)).toBeGreaterThanOrEqual(41)
})

/**
 * The ORE opclass is superuser-only. This is the observable difference between
 * the two database variants, and the reason the nine `_ord_ore` domains are
 * `deferred` in the catalog: on managed Postgres their columns exist and compare
 * correctly, but `ORDER BY eql_v3.ord_term_ore(col)` silently falls back to raw
 * bytea order. Pinning it here means a bundle change that alters the privilege
 * story shows up as a harness failure rather than as a mysterious ordering bug.
 */
it('installs the ORE opclass only when the connecting role is a superuser', async () => {
  const [role] = await sql<{ is_super: boolean }[]>`
    SELECT rolsuper AS is_super FROM pg_roles WHERE rolname = current_user
  `
  const [opclass] = await sql<{ count: string }[]>`
    SELECT count(*)::text AS count
    FROM pg_opclass o
    JOIN pg_namespace n ON n.oid = o.opcnamespace
    WHERE n.nspname LIKE 'eql_v3%'
  `

  const opclasses = Number(opclass?.count)
  if (role?.is_super) {
    expect(opclasses).toBeGreaterThan(0)
  } else {
    expect(opclasses).toBe(0)
  }
})

/**
 * Both database variants are asserted, neither is skipped.
 *
 * A skipped test reads exactly like a passing one, and the two skips that used to
 * live here hid a real bug: `dbVariant()` inferred `postgres` for the Drizzle job
 * running against `supabase/postgres`, so EQL installed without `--supabase`, the
 * grants were never applied, and the grants test quietly did not run.
 *
 * So assert the whole truth: on a Supabase database the roles exist and hold the
 * grants; on a plain one they do not exist at all.
 */
it('applies the anon grants on Supabase, and has no such roles on plain Postgres', async () => {
  const [roles] = await sql<{ count: string }[]>`
    SELECT count(*)::text AS count FROM pg_roles
    WHERE rolname IN ('anon', 'authenticated', 'service_role')
  `

  if (dbVariant() === 'supabase') {
    expect(Number(roles?.count)).toBe(3)

    // `eql_v3_internal` is load-bearing: the SECURITY INVOKER extractors resolve
    // it with the CALLER's privileges, so without this grant every encrypted
    // filter fails for `anon` with "permission denied for schema".
    const [privs] = await sql<{ eql_v3: boolean; internal: boolean }[]>`
      SELECT has_schema_privilege('anon', 'eql_v3', 'USAGE') AS eql_v3,
             has_schema_privilege('anon', 'eql_v3_internal', 'USAGE') AS internal
    `
    expect(privs).toEqual({ eql_v3: true, internal: true })
    return
  }

  // Plain Postgres: the Supabase roles do not exist, so there is nothing to
  // grant. Asserting their ABSENCE is what makes the variant claim falsifiable —
  // if this database ever grew them, the `--supabase` install path would have to
  // run here too.
  expect(Number(roles?.count)).toBe(0)
})

/**
 * PostgREST is asserted on its own axis, not on the variant. The Drizzle job runs
 * against the Supabase database and does not need PostgREST; conflating "is this
 * Supabase" with "is PostgREST up" is precisely what made `dbVariant()` lie.
 */
it('serves PostgREST when configured, and is not configured otherwise', async () => {
  const url = process.env['PGRST_URL']

  if (!url) {
    // Only the plain-Postgres compose file omits PostgREST. A Supabase database
    // with no `PGRST_URL` means the job forgot to pass it.
    expect(dbVariant()).toBe('postgres')
    return
  }

  const response = await fetch(`${pgrestUrl()}/`)

  expect(response.status).toBe(200)
})
