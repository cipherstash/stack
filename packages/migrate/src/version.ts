import type { ClientBase } from 'pg'

/**
 * Which EQL generation an encrypted column belongs to. The migration lifecycle
 * differs between them: v2 is driven by the `eql_v2_configuration` state machine
 * (see {@link import('./eql.js')}), while v3 is domain-native — configuration
 * lives in the column's own type and there is no configuration table, so its
 * lifecycle is backfill-then-drop with no cut-over rename.
 */
export type EqlVersion = 'v2' | 'v3'

/**
 * Detect the EQL version of a column by inspecting its Postgres type.
 *
 * - v2 encrypted columns are the `public.eql_v2_encrypted` domain.
 * - v3 encrypted columns are a concrete `eql_v3_*` domain (e.g.
 *   `eql_v3_text_search`, `eql_v3_int8_ord`).
 * - Anything else — a plaintext column, or a column/table that doesn't exist —
 *   returns `null`.
 *
 * Pass the **encrypted target** column (e.g. `email_encrypted`), not the
 * plaintext source: it's the encrypted column whose domain type carries the EQL
 * generation. `tableName` may be schema-qualified (`"schema.table"`);
 * resolution honours the connection's `search_path` via `to_regclass`.
 */
export async function detectColumnEqlVersion(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<EqlVersion | null> {
  // `a.atttypid` on a domain-typed column is the DOMAIN's oid, so `t.typname`
  // is the domain name (e.g. `eql_v2_encrypted`), not the underlying `jsonb`.
  // `to_regclass` returns NULL for an unknown table → no rows → null.
  const result = await client.query<{ domain_name: string }>(
    `SELECT t.typname AS domain_name
       FROM pg_attribute a
       JOIN pg_type t ON t.oid = a.atttypid
      WHERE a.attrelid = to_regclass($1)
        AND a.attname = $2
        AND NOT a.attisdropped`,
    [tableName, columnName],
  )
  const domain = result.rows[0]?.domain_name
  if (domain === undefined) return null
  if (domain === 'eql_v2_encrypted') return 'v2'
  if (domain.startsWith('eql_v3')) return 'v3'
  return null
}
