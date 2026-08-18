/**
 * The Supabase grants blocks, as pure strings.
 *
 * Deliberately import-free. `installer/index.ts` pulls in `pg` and the EQL SQL
 * bundle, which no other package depends on; keeping the grants here lets the
 * live proof in `packages/stack/__tests__/supabase-v3-grants-pg.test.ts` assert
 * against the EXACT SQL this package ships, without `@cipherstash/stack` taking
 * a dependency on `stash` (which would be a cycle — `stash` already depends on
 * `@cipherstash/stack`). Re-exported from `installer/index.ts`, which remains
 * the public entry point.
 */

/**
 * EQL v3 installs its operator functions into `eql_v3` (constructors live in
 * `eql_v3_internal`; the scalar type domains live in `public`). The `eql_v3`
 * schema is the install-detection target, and BOTH schemas are grant targets —
 * see {@link supabaseInternalPermissionsSql}.
 */
export const EQL_V3_SCHEMA_NAME = 'eql_v3'
export const EQL_V3_INTERNAL_SCHEMA_NAME = 'eql_v3_internal'

/**
 * Build the SQL block that grants an EQL schema, tables, routines, and
 * sequences to Supabase's built-in roles (`anon`, `authenticated`,
 * `service_role`).
 *
 * Supabase uses dedicated roles that don't own the schema, so explicit grants
 * are required. Returned as a single multi-statement string so it can be
 * executed in one `client.query()` (Postgres accepts multi-statement strings)
 * AND embedded directly into a Supabase migration file. One source of truth
 * for both the runtime install path and the generated migration file.
 */
export function supabasePermissionsSql(schemaName: string): string {
  return (
    supabaseImmediateGrantsSql(schemaName) +
    supabaseDefaultPrivilegesSql(schemaName)
  )
}

/**
 * The plain `GRANT` statements of {@link supabasePermissionsSql} — executable
 * by any role that owns the schema (i.e. the role that just ran the EQL
 * install), with no membership of `postgres` required.
 */
export function supabaseImmediateGrantsSql(schemaName: string): string {
  return `GRANT USAGE ON SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL ROUTINES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
`
}

/**
 * The owner-scoped `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements of
 * {@link supabasePermissionsSql}. These cover objects `postgres` creates in the
 * schema *later*, and Postgres only lets a member of `postgres` run them — on
 * managed platforms where the connecting role is not (e.g. Lovable's
 * `sandbox_exec`), they fail with `permission denied to change default
 * privileges` while every statement in
 * {@link supabaseImmediateGrantsSql} succeeds. The installer defers them for
 * such roles instead of failing the install.
 */
export function supabaseDefaultPrivilegesSql(schemaName: string): string {
  return `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${schemaName} GRANT SELECT ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${schemaName} GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${schemaName} GRANT USAGE ON SEQUENCES TO anon, authenticated, service_role;
`
}

/**
 * Grants a *supporting* EQL schema that holds only routines and types — no
 * tables or sequences to grant.
 *
 * Load-bearing for EQL v3. Every public entry point the query path touches
 * (`eql_v3.eq_term`, `ord_term`, `match_term` — 68 of their 69 overloads) is
 * SECURITY INVOKER and qualifies `eql_v3_internal.*` by name in its body.
 * Postgres resolves those names with the CALLER's privileges, and schema USAGE
 * is checked at name resolution. Without USAGE on `eql_v3_internal`, `anon` and
 * `authenticated` get `permission denied for schema eql_v3_internal` on EVERY
 * encrypted filter — `=`, `>=`, and `@>` alike, since each routes through a
 * term extractor. The default PUBLIC EXECUTE on functions means USAGE is the
 * only real barrier; EXECUTE is granted too so an install into a database that
 * has revoked EXECUTE from PUBLIC still works.
 *
 */
export function supabaseInternalPermissionsSql(schemaName: string): string {
  return (
    supabaseInternalImmediateGrantsSql(schemaName) +
    supabaseInternalDefaultPrivilegesSql(schemaName)
  )
}

/** The plain-`GRANT` half of {@link supabaseInternalPermissionsSql}. */
export function supabaseInternalImmediateGrantsSql(schemaName: string): string {
  return `GRANT USAGE ON SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL ROUTINES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
`
}

/**
 * The owner-scoped half of {@link supabaseInternalPermissionsSql}. See
 * {@link supabaseDefaultPrivilegesSql} for why it is separable.
 */
export function supabaseInternalDefaultPrivilegesSql(
  schemaName: string,
): string {
  return `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${schemaName} GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
`
}

/**
 * The v3 Supabase grants block: `eql_v3` (the public surface) AND
 * `eql_v3_internal` (which its function bodies reach into). See
 * {@link supabaseInternalPermissionsSql} for why the second block is required.
 */
export const SUPABASE_PERMISSIONS_SQL_V3 =
  supabasePermissionsSql(EQL_V3_SCHEMA_NAME) +
  supabaseInternalPermissionsSql(EQL_V3_INTERNAL_SCHEMA_NAME)

/**
 * The immediate half of {@link SUPABASE_PERMISSIONS_SQL_V3}: every plain
 * `GRANT`, both schemas. Runnable by the role that installed EQL, whatever
 * its memberships.
 */
export const SUPABASE_IMMEDIATE_GRANTS_SQL_V3 =
  supabaseImmediateGrantsSql(EQL_V3_SCHEMA_NAME) +
  supabaseInternalImmediateGrantsSql(EQL_V3_INTERNAL_SCHEMA_NAME)

/**
 * The owner-scoped half of {@link SUPABASE_PERMISSIONS_SQL_V3}: the
 * `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements, both schemas.
 * Requires membership of `postgres`; the installer defers these (and prints
 * them, prefixed with {@link DEFERRED_GRANTS_HEADER}) when the connecting
 * role is not a member.
 *
 * Note the two constants reorder statements relative to
 * `SUPABASE_PERMISSIONS_SQL_V3` (immediate for both schemas, then deferred
 * for both) — the statements are order-independent across schemas, and
 * `SUPABASE_PERMISSIONS_SQL_V3` itself keeps its original byte-exact order.
 */
export const SUPABASE_DEFAULT_PRIVILEGES_SQL_V3 =
  supabaseDefaultPrivilegesSql(EQL_V3_SCHEMA_NAME) +
  supabaseInternalDefaultPrivilegesSql(EQL_V3_INTERNAL_SCHEMA_NAME)

/**
 * Comment prefix for the deferred owner-scoped statements when they are
 * printed for the operator (or a future `--print-sql`) instead of executed.
 */
export const DEFERRED_GRANTS_HEADER = `-- The statements below require a role that is a member of \`postgres\`.
-- Apply them via your platform's migration tool or the Supabase SQL editor.
`
