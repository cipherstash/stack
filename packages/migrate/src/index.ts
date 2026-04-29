/**
 * `@cipherstash/migrate` — primitives for migrating existing plaintext
 * columns to `eql_v2_encrypted` in production Postgres databases.
 *
 * Powers the `stash encrypt` CLI command group, and is usable directly
 * from a user's own worker/cron when they'd rather not pipe gigabytes
 * through a CLI process.
 *
 * Per-column lifecycle:
 *
 * ```
 * schema-added → dual-writing → backfilling → backfilled → cut-over → dropped
 * ```
 *
 * State is split across three stores on purpose:
 * - `.cipherstash/migrations.json` — repo-side intent ({@link Manifest})
 * - `eql_v2_configuration` — EQL intent (unchanged; Proxy's source of truth)
 * - `cipherstash.cs_migrations` — append-only runtime state written here
 *
 * The primary entry point is {@link runBackfill}. The state DAO
 * ({@link appendEvent}, {@link latestByColumn}, {@link progress}) lets you
 * build your own UI on top of the same tracking table.
 *
 * @packageDocumentation
 */

export { installMigrationsSchema, MIGRATIONS_SCHEMA_SQL } from './install.js'
export {
  appendEvent,
  latestByColumn,
  progress,
  type MigrationEvent,
  type MigrationPhase,
  type MigrationStateRow,
  type ColumnKey,
} from './state.js'
export {
  selectPendingColumns,
  readyForEncryption,
  renameEncryptedColumns,
  reloadConfig,
  countEncryptedWithActiveConfig,
} from './eql.js'
export {
  fetchUnencryptedPage,
  countUnencrypted,
  qualifyTable,
  type KeysetPage,
  type KeysetPageOptions,
} from './cursor.js'
export { quoteIdent } from './sql.js'
export {
  runBackfill,
  type BackfillOptions,
  type BackfillProgress,
  type BackfillResult,
} from './backfill.js'
export {
  readManifest,
  writeManifest,
  manifestPath,
  type Manifest,
  type ManifestColumn,
} from './manifest.js'
