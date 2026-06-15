import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import type postgres from 'postgres'

const SQL_PATH = fileURLToPath(
  new URL('../../fixtures/cipherstash-encrypt-v3.sql', import.meta.url),
)

/**
 * Installs the v3 SQL. Multi-statement DDL requires sql.unsafe (tagged-template
 * sql`` runs a single statement).
 *
 * Idempotency is GUARDED, not via CREATE OR REPLACE: the EQL v3 SQL hardcodes the
 * `eql_v3` schema and its `CREATE DOMAIN`/`CREATE OPERATOR` have no OR REPLACE, so a
 * blind re-install errors on the second run. We therefore probe for `eql_v3.text_eq`
 * and skip the install if it already exists.
 *
 * The probe-then-install runs inside ONE transaction holding a transaction-scoped
 * advisory lock, so it is also concurrency-safe: the `eql_v3` schema is global and
 * shared across the protect/stack/drizzle suites Turbo runs, and without the lock
 * two suites could both pass the probe before either installs, then race on
 * `CREATE DOMAIN` (which has no OR REPLACE). A `pg_advisory_xact_lock` serialises
 * that window — the first holder installs, the rest see `text_eq` present and
 * no-op (§9b). It MUST be a transaction (not a bare session lock): `sql` is a
 * connection pool, so a session lock and its unlock could land on different pooled
 * connections (and would not survive PgBouncer transaction mode). A single
 * `sql.begin` keeps the lock, probe, and install on one connection and auto-releases
 * the lock at commit.
 */
const INSTALL_LOCK_KEY = 'eql_v3_install'

export async function installEqlV3(sql: postgres.Sql): Promise<void> {
  const ddl = readFileSync(SQL_PATH, 'utf-8')
  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext(${INSTALL_LOCK_KEY}))`
    const [present] = await tx`
      SELECT 1 FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'eql_v3' AND t.typname = 'text_eq'
    `
    if (present) return // already installed by an earlier run / sibling suite
    await tx.unsafe(ddl)
  })
}
