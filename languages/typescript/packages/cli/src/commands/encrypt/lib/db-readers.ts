import { latestByColumn } from '@cipherstash/migrate'
import type pg from 'pg'

/**
 * `latestByColumn` from `@cipherstash/migrate`, but tolerant of the
 * pre-install case where `cipherstash.cs_migrations` doesn't exist.
 * The encryption-rollout commands all need to be readable on a fresh
 * project; treating "table missing" as "no events" keeps them so.
 */
export async function latestByColumnSafe(
  client: pg.ClientBase,
): Promise<
  ReturnType<typeof latestByColumn> extends Promise<infer T> ? T : never
> {
  try {
    return (await latestByColumn(client)) as Awaited<
      ReturnType<typeof latestByColumn>
    >
  } catch (err) {
    if (
      err instanceof Error &&
      /cs_migrations|schema "cipherstash"/i.test(err.message)
    ) {
      return new Map() as Awaited<ReturnType<typeof latestByColumn>>
    }
    throw err
  }
}

export interface EqlColumnInfo {
  /** Index kinds attached to this column in the EQL config (`unique`,
   *  `match`, `ore`, `ste_vec`). Empty when no indexes are configured. */
  indexes: string[]
  /** Lifecycle state of the EQL config row this column belongs to. */
  state: 'active' | 'pending' | 'encrypting'
}

/**
 * Read every column registered in `eql_v2_configuration` (active,
 * pending, or encrypting) keyed by `<table>.<column>`. Active rows win
 * when a column appears in more than one state.
 *
 * The call is best-effort: if `eql_v2_configuration` doesn't exist yet
 * (EQL not installed), an empty map is returned instead of throwing.
 */
export async function fetchActiveEqlConfig(
  client: pg.ClientBase,
): Promise<Map<string, EqlColumnInfo>> {
  const out = new Map<string, EqlColumnInfo>()
  try {
    const result = await client.query<{ state: string; data: unknown }>(
      `SELECT state, data FROM public.eql_v2_configuration
       WHERE state IN ('active', 'pending', 'encrypting')
       ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'encrypting' THEN 1 ELSE 2 END`,
    )
    for (const row of result.rows) {
      const data = row.data as {
        tables?: Record<
          string,
          Record<string, { indexes?: Record<string, unknown> }>
        >
      } | null
      if (!data?.tables) continue
      for (const [tableName, columns] of Object.entries(data.tables)) {
        for (const [columnName, column] of Object.entries(columns)) {
          const key = `${tableName}.${columnName}`
          if (out.has(key)) continue
          out.set(key, {
            indexes: Object.keys(column.indexes ?? {}),
            state: row.state as 'active' | 'pending' | 'encrypting',
          })
        }
      }
    }
  } catch (err) {
    if (err instanceof Error && /eql_v2_configuration/i.test(err.message)) {
      return out
    }
    throw err
  }
  return out
}

/**
 * Read `information_schema.columns` and group columns by table, mapping each
 * column name to its DOMAIN type (or `null` for plain types). The domain is
 * what makes EQL columns self-describing (`eql_v2_encrypted` / `eql_v3_*`),
 * so callers can classify encryption state from the types themselves rather
 * than relying on the `<col>_encrypted` naming convention.
 *
 * When `tables` is provided the query is constrained to that set —
 * status's quest log only ever needs ~5 specific tables, so passing
 * the manifest's tables avoids a full-schema scan.
 */
export async function fetchPhysicalColumns(
  client: pg.ClientBase,
  tables?: ReadonlyArray<string>,
): Promise<Map<string, Map<string, string | null>>> {
  const out = new Map<string, Map<string, string | null>>()
  type Row = {
    table_name: string
    column_name: string
    domain_name: string | null
  }
  try {
    const result =
      tables === undefined
        ? await client.query<Row>(
            `SELECT table_name, column_name, domain_name
             FROM information_schema.columns
             WHERE table_schema = current_schema()`,
          )
        : await client.query<Row>(
            `SELECT table_name, column_name, domain_name
             FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = ANY($1::text[])`,
            [tables],
          )
    for (const row of result.rows) {
      const cols = out.get(row.table_name) ?? new Map<string, string | null>()
      cols.set(row.column_name, row.domain_name)
      out.set(row.table_name, cols)
    }
  } catch {
    // information_schema is always present; failures here are surprising
    // enough to swallow rather than crash the read-only status path.
  }
  return out
}
