import type { ClientBase } from 'pg'

/**
 * DDL for `cipherstash.cs_migrations` — the append-only per-column event
 * log that tracks encryption-migration runtime state (phase, backfill
 * cursor, rows processed). Installed by `stash eql install`.
 *
 * All statements are `CREATE … IF NOT EXISTS` so running the installer
 * multiple times or alongside an existing deployment is safe.
 *
 * This table is intentionally independent of the installed EQL schemas, so
 * checkpoint writes never depend on query-configuration state.
 */
export const MIGRATIONS_SCHEMA_SQL = `
CREATE SCHEMA IF NOT EXISTS cipherstash;

CREATE TABLE IF NOT EXISTS cipherstash.cs_migrations (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  table_name     text NOT NULL,
  column_name    text NOT NULL,
  event          text NOT NULL,
  phase          text NOT NULL,
  cursor_value   text,
  rows_processed bigint,
  rows_total     bigint,
  details        jsonb,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cs_migrations_column_id_desc
  ON cipherstash.cs_migrations (table_name, column_name, id DESC);
`

/**
 * Create the `cipherstash` schema and `cs_migrations` table if they do not
 * already exist. Safe to call on every `stash eql install` invocation.
 *
 * Requires `CREATE SCHEMA` privileges on the database. If the caller lacks
 * them, the query will fail and the error bubbles up — the CLI currently
 * warns but does not abort, on the theory that a human DBA can install
 * this schema out-of-band using `MIGRATIONS_SCHEMA_SQL` directly.
 */
export async function installMigrationsSchema(
  client: ClientBase,
): Promise<void> {
  await client.query(MIGRATIONS_SCHEMA_SQL)
}
