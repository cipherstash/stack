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
 * And the reverse lifecycle `stash decrypt` drives, back to plaintext, on the
 * same chunked engine ({@link runDecryptBackfill}):
 *
 * ```
 * decrypt-dual-writing → decrypting → decrypted → encrypted-dropped
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
  ColumnMigration,
  ColumnMigrationError,
  type ColumnMigrationState,
  DIRECTION_VOCABULARY,
  type DirectionVocabulary,
  deriveColumnMigration,
  deriveTwinName,
  type ForcedBy,
  type LoadColumnMigrationOptions,
  type MigrationDirection,
  manifestTwin,
  type Obligation,
  type OpenCounterpart,
  openCounterpart,
  type PassPlan,
  type PassProgress,
  passProgress,
  planPassFor,
  type TwinSource,
  type Waiver,
} from './column-migration.js'
export {
  columnHasValues,
  countEncrypted,
  countUndecrypted,
  countUnencrypted,
  type DecryptKeysetPageOptions,
  fetchUndecryptedPage,
  fetchUnencryptedPage,
  type KeysetBound,
  type KeysetPage,
  type KeysetPageOptions,
  qualifyTable,
} from './cursor.js'
export {
  type BulkDecryptItem,
  type BulkDecryptResult,
  type DecryptBackfillOptions,
  type DecryptBackfillProgress,
  type DecryptBackfillResult,
  type DecryptionClientLike,
  formatCodes,
  MAX_DECRYPT_CHUNK_SIZE,
  NULL_PLAINTEXT_SAMPLE_SIZE,
  PlaintextWriteError,
  plaintextSerializer,
  runDecryptBackfill,
  UndecryptableBatchError,
} from './decrypt.js'
export {
  type ChunkContext,
  type ChunkedRunOptions,
  type ChunkedRunProgress,
  type ChunkedRunResult,
  type PassMode,
  type PreparedChunk,
  runChunkedMigration,
} from './engine.js'
export { installMigrationsSchema, MIGRATIONS_SCHEMA_SQL } from './install.js'
export {
  type Manifest,
  type ManifestColumn,
  manifestPath,
  readManifest,
  removeManifestColumn,
  setManifestTargetPhase,
  upsertManifestColumn,
  writeManifest,
} from './manifest.js'
export {
  type EqlDomainFamily,
  type PlaintextSqlType,
  type PlaintextTypeMapping,
  plaintextTypeForEqlDomain,
} from './plaintext-type.js'
export { quoteIdent } from './sql.js'
export {
  appendEvent,
  type ColumnKey,
  isReverseMigrationPhase,
  latestByColumn,
  type MigrationEvent,
  type MigrationPhase,
  type MigrationStateRow,
  progress,
  REVERSE_MIGRATION_PHASES,
  type ReverseMigrationEvent,
  type ReverseMigrationPhase,
} from './state.js'
export {
  type ColumnIndexInfo,
  classifyEqlDomain,
  columnExists,
  columnSqlType,
  countEqlColumnsInDatabase,
  detectColumnEqlVersion,
  type EncryptedColumnInfo,
  type EncryptedColumnResolution,
  EQL_COLUMN_PREDICATE_SQL,
  type EqlVersion,
  listColumnIndexes,
  listEncryptedColumns,
  pickEncryptedColumn,
  primaryKeyColumns,
  type ResolvedEncryptedColumn,
  resolveEncryptedColumn,
} from './version.js'
