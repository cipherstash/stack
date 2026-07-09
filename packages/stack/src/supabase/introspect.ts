/** One introspected column: its DB name and its `public` EQL v3 domain (or `null`). */
export interface IntrospectedColumn {
  columnName: string
  domainName: string | null
}

/** One introspected base table with its columns in ordinal order. */
export interface IntrospectedTable {
  tableName: string
  columns: IntrospectedColumn[]
}

export type IntrospectionResult = IntrospectedTable[]

/**
 * Raw `information_schema` column row. `domain_name` is the column's domain when
 * that domain lives in `public`, else `NULL` (the query nulls out non-`public`
 * domains — see the CASE below), so a same-named domain in another schema is
 * never mistaken for an EQL v3 domain.
 */
export interface IntrospectionRow {
  table_name: string
  column_name: string
  domain_name: string | null
}

/** Tables + the set of `public` domains recognised as EQL v3 (modelled or not). */
export interface IntrospectionData {
  tables: IntrospectionResult
  eqlDomains: Set<string>
}

/**
 * Group flat `information_schema` rows into tables. Row order is the query's
 * `ORDER BY table_name, ordinal_position`, so pushing in order preserves both
 * table grouping and per-table column order.
 */
export function groupIntrospectionRows(
  rows: IntrospectionRow[],
): IntrospectionResult {
  const byTable = new Map<string, IntrospectedColumn[]>()
  const order: string[] = []
  for (const row of rows) {
    let cols = byTable.get(row.table_name)
    if (!cols) {
      cols = []
      byTable.set(row.table_name, cols)
      order.push(row.table_name)
    }
    cols.push({ columnName: row.column_name, domainName: row.domain_name })
  }
  return order.map((tableName) => ({
    tableName,
    columns: byTable.get(tableName) as IntrospectedColumn[],
  }))
}

// DELIBERATE FORK of packages/cli/src/commands/init/lib/introspect.ts — keep the
// two in sync. `stack` cannot depend on `cli`, and the projections differ: the
// CLI detects v2 composites via `udt_name = 'eql_v2_encrypted'`; this reads v3
// domains via `domain_name`. `udt_name` is `jsonb` for a v3 domain column, so it
// cannot be reused here.
const COLUMNS_QUERY = `
  SELECT
    c.table_name,
    c.column_name,
    CASE WHEN c.domain_schema = 'public' THEN c.domain_name ELSE NULL END
      AS domain_name
  FROM information_schema.columns c
  JOIN information_schema.tables t
    ON t.table_name = c.table_name AND t.table_schema = c.table_schema
  WHERE c.table_schema = 'public'
    AND t.table_type = 'BASE TABLE'
  ORDER BY c.table_name, c.ordinal_position
`

// The authoritative EQL-domain signal is the domain's COMMENT: every EQL v3
// domain in the bundle is `COMMENT ON DOMAIN public.<name> IS 'EQL…'` (89/89,
// zero exceptions). The CHECK bodies are NOT usable — they are non-uniform
// (`integer_ord` names no function; `json` calls a `public.eql_v3_*` function).
// `obj_description(oid, 'pg_type')` reads that comment for a domain type.
const EQL_DOMAINS_QUERY = `
  SELECT tp.typname AS domain_name
  FROM pg_type tp
  JOIN pg_namespace ns ON ns.oid = tp.typnamespace
  WHERE tp.typtype = 'd'
    AND ns.nspname = 'public'
    AND obj_description(tp.oid, 'pg_type') LIKE 'EQL%'
`

/** `pg` ships its API on the CJS default export, not the module namespace. */
type PgDefaultExport = typeof import('pg')['default']

/**
 * `pg` is an optional peer dependency, so a missing install surfaces here as a
 * module-resolution error. Remap it to the actionable message; let every other
 * failure propagate. Guard on `err.code` rather than message text — CJS throws
 * `MODULE_NOT_FOUND`, ESM throws `ERR_MODULE_NOT_FOUND`.
 *
 * `importPg` is injectable because `vi.mock` cannot reproduce a module that
 * fails to resolve — it replaces any factory rejection with its own error,
 * discarding the `code` this function branches on.
 *
 * @internal
 */
export async function loadPg(
  importPg: () => Promise<{ default: PgDefaultExport }> = () => import('pg'),
) {
  try {
    const { default: pg } = await importPg()
    return pg
  } catch (err) {
    const code = (err as { code?: string }).code
    if (code !== 'MODULE_NOT_FOUND' && code !== 'ERR_MODULE_NOT_FOUND')
      throw err
    throw new Error(
      '[supabase v3]: encryptedSupabaseV3 introspects the database over a direct ' +
        "Postgres connection, but the optional peer dependency 'pg' is not installed. " +
        'Install it (`npm install pg`). This also means encryptedSupabaseV3 cannot run ' +
        'in a Worker or the browser — use encryptedSupabase (EQL v2) there.',
      { cause: err },
    )
  }
}

/**
 * Connect over `databaseUrl`, read every base table in the `public` schema with
 * its EQL v3 domain (`domain_name`), and the set of `public` domains recognised
 * as EQL v3 (by their `COMMENT`). `pg` is loaded with a dynamic import so
 * bundlers do not pull it in unless introspection runs.
 *
 * `udt_name` is `jsonb` for a domain column, so ONLY `domain_name` distinguishes
 * an EQL v3 column from a plain `jsonb` column (whose `domain_name` is NULL).
 */
export async function introspect(
  databaseUrl: string,
): Promise<IntrospectionData> {
  const pg = await loadPg()
  // Mirror the CLI introspector's bounded connect so an unreachable DB fails
  // fast rather than hanging construction.
  const client = new pg.Client({
    connectionString: databaseUrl,
    connectionTimeoutMillis: 10_000,
  })
  await client.connect()
  try {
    const [columns, domains] = await Promise.all([
      client.query<IntrospectionRow>(COLUMNS_QUERY),
      client.query<{ domain_name: string }>(EQL_DOMAINS_QUERY),
    ])
    return {
      tables: groupIntrospectionRows(columns.rows),
      eqlDomains: new Set(domains.rows.map((r) => r.domain_name)),
    }
  } finally {
    // `end()` runs only after a successful connect; swallow its own failure so it
    // can never mask a query error (and, on the connect-failure path above,
    // `connect()` throws before this try/finally is entered at all).
    await client.end().catch(() => {})
  }
}
