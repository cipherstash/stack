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

/** EQL v2's operator schema. It has no internal schema. */
export const EQL_SCHEMA_NAME = 'eql_v2'

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
 * for both the runtime install path and the generated migration file, shared
 * by the v2 (`eql_v2`) and v3 (`eql_v3`) installs.
 */
export function supabasePermissionsSql(schemaName: string): string {
  return `GRANT USAGE ON SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL ROUTINES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${schemaName} GRANT SELECT ON TABLES TO anon, authenticated, service_role;
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
 * `eql_v2` has no internal schema, so this applies to v3 only.
 */
export function supabaseInternalPermissionsSql(schemaName: string): string {
  return `GRANT USAGE ON SCHEMA ${schemaName} TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL ROUTINES IN SCHEMA ${schemaName} TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${schemaName} GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
`
}

/** The v2 (`eql_v2`) Supabase grants block. See {@link supabasePermissionsSql}. */
export const SUPABASE_PERMISSIONS_SQL = supabasePermissionsSql(EQL_SCHEMA_NAME)

/**
 * The v3 Supabase grants block: `eql_v3` (the public surface) AND
 * `eql_v3_internal` (which its function bodies reach into). See
 * {@link supabaseInternalPermissionsSql} for why the second block is required.
 */
export const SUPABASE_PERMISSIONS_SQL_V3 =
  supabasePermissionsSql(EQL_V3_SCHEMA_NAME) +
  supabaseInternalPermissionsSql(EQL_V3_INTERNAL_SCHEMA_NAME)
