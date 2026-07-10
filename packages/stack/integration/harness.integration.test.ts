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

it.runIf(dbVariant() === 'supabase')(
  'grants anon USAGE on both eql_v3 and eql_v3_internal',
  async () => {
    // `eql_v3_internal` is load-bearing: the SECURITY INVOKER extractors resolve
    // it with the CALLER's privileges, so without this grant every encrypted
    // filter fails for `anon` with "permission denied for schema".
    const [row] = await sql<{ eql_v3: boolean; internal: boolean }[]>`
      SELECT has_schema_privilege('anon', 'eql_v3', 'USAGE') AS eql_v3,
             has_schema_privilege('anon', 'eql_v3_internal', 'USAGE') AS internal
    `

    expect(row).toEqual({ eql_v3: true, internal: true })
  },
)

it.runIf(dbVariant() === 'supabase')(
  'serves PostgREST as anon through the authenticator role',
  async () => {
    const response = await fetch(`${pgrestUrl()}/`)

    expect(response.status).toBe(200)
  },
)
