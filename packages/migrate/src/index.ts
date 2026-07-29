/**
 * `@cipherstash/migrate` — primitives for migrating existing plaintext
 * columns to self-describing EQL v3 domains in production Postgres databases.
 *
 * Powers the `stash encrypt` CLI command group, and is usable directly
 * from a user's own worker/cron when they'd rather not pipe gigabytes
 * through a CLI process.
 *
 * Per-column lifecycle (the application switches to the encrypted column by
 * name; there is no automated cut-over rename):
 *
 * ```
 * v3: schema-added → dual-writing → backfilling → backfilled → dropped
 * ```
 *
 * State is split across three stores on purpose:
 * - `.cipherstash/migrations.json` — repo-side intent ({@link Manifest})
 * - `cipherstash.cs_migrations` — append-only runtime state written here
 *
 * The primary entry point is {@link runBackfill}. The state DAO
 * ({@link appendEvent}, {@link latestByColumn}, {@link progress}) lets you
 * build your own UI on top of the same tracking table.
 *
 * @packageDocumentation
 */

export {
  type BackfillOptions,
  type BackfillProgress,
  type BackfillResult,
  runBackfill,
} from './backfill.js'
export {
  countEncrypted,
  countUnencrypted,
  fetchUnencryptedPage,
  type KeysetPage,
  type KeysetPageOptions,
  qualifyTable,
} from './cursor.js'
export { installMigrationsSchema, MIGRATIONS_SCHEMA_SQL } from './install.js'
export {
  type Manifest,
  type ManifestColumn,
  manifestPath,
  readManifest,
  setManifestTargetPhase,
  upsertManifestColumn,
  writeManifest,
} from './manifest.js'
export { quoteIdent } from './sql.js'
export {
  appendEvent,
  type ColumnKey,
  latestByColumn,
  type MigrationEvent,
  type MigrationPhase,
  type MigrationStateRow,
  progress,
} from './state.js'
export {
  classifyEqlDomain,
  columnExists,
  detectColumnEqlVersion,
  type EncryptedColumnInfo,
  type EncryptedColumnResolution,
  type EqlVersion,
  listEncryptedColumns,
  pickEncryptedColumn,
  type ResolvedEncryptedColumn,
  resolveEncryptedColumn,
} from './version.js'
