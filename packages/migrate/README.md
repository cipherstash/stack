# @cipherstash/migrate

Primitives for migrating existing plaintext columns to CipherStash encrypted columns (EQL v2 `eql_v2_encrypted` or the concrete EQL v3 `eql_v3_*` domains) in production Postgres databases, safely and resumably.

Backs the `stash encrypt` CLI command group, but also exported for direct use — embed `runBackfill()` in your own worker or cron job when you'd rather not pipe gigabytes through a CLI process.

## Lifecycle

Each column walks through these phases — the ladder depends on the column's EQL version (auto-detected from its Postgres domain type via `detectColumnEqlVersion`):

```
EQL v2: schema-added → dual-writing → backfilling → backfilled → cut-over → dropped
EQL v3: schema-added → dual-writing → backfilling → backfilled ————————————→ dropped
```

State is tracked in an append-only `cipherstash.cs_migrations` table installed by `stash eql install`.

- **EQL v2** additionally keeps its intent (indexes, cast_as) in `eql_v2_configuration` so CipherStash Proxy works against the same database, and finishes with a **cut-over**: `eql_v2.rename_encrypted_columns()` swaps `<col>_encrypted` into place (`<col>` becomes `<col>_plaintext`) alongside a config promotion.
- **EQL v3** has **no configuration table and no cut-over** — each column's domain type encodes its own configuration. The application switches to `<col>_encrypted` *by name*, and the original plaintext `<col>` is dropped once verified. Backfill verification is a plain count of the populated target column (`countEncrypted`); the concrete `eql_v3_*` domain's CHECK constraint guarantees every non-null value is a valid v3 envelope.

## API

```ts
import {
  installMigrationsSchema,
  appendEvent,
  latestByColumn,
  progress,
  runBackfill,
  renameEncryptedColumns,
  reloadConfig,
  readManifest,
  writeManifest,
} from '@cipherstash/migrate'
```

### `installMigrationsSchema(client)`

Creates `cipherstash.cs_migrations` idempotently. Normally called by `stash eql install`.

### `runBackfill({ db, encryptionClient, tableSchema, tableName, plaintextColumn, encryptedColumn, pkColumn, schemaColumnKey, chunkSize?, signal?, onProgress? })`

Chunked, resumable, idempotent backfill of plaintext → encrypted. Per chunk, in a single transaction: select next page → encrypt via `client.bulkEncryptModels` → `UPDATE … FROM (VALUES …)` → `INSERT` a `backfill_checkpoint` event. Guards with `encrypted IS NULL` so re-runs never double-write.

- `db`: a `pg.PoolClient` (the runner drives transactions on it).
- `encryptionClient`: your initialised `@cipherstash/stack` client (or anything that exposes `bulkEncryptModels(models, table)` returning `{ data } | { failure }`). For an EQL v3 column pass an `EncryptionV3` client (from `@cipherstash/stack/v3`) — it pins the v3 wire format; the engine itself is version-agnostic and writes whatever envelope the client produces.
- `tableSchema`: the `EncryptedTable` for the target table from your encryption client file.
- `signal`: optional `AbortSignal`. If aborted between chunks, the backfill exits cleanly and leaves a resumable checkpoint.

Returns `{ resumed, rowsProcessed, rowsTotal, completed }`.

### `appendEvent(client, { tableName, columnName, event, phase, … })` / `progress(client, table, column)` / `latestByColumn(client)`

Direct access to the `cs_migrations` event log. Use these if you're building your own migration UI or orchestration on top.

### `renameEncryptedColumns(client)` / `reloadConfig(client)`

Thin wrappers around `eql_v2.rename_encrypted_columns()` (the **v2** cut-over primitive) and `eql_v2.reload_config()` (Proxy refresh hint — no-op when connected directly to Postgres). Not used in the v3 lifecycle — v3 has no rename step.

### `detectColumnEqlVersion(client, table, column)` / `countEncrypted(client, table, column)`

`detectColumnEqlVersion` inspects the column's Postgres domain type and returns `'v2'`, `'v3'`, or `null` (not an EQL column) — the branch point for everything version-specific above. `countEncrypted` counts populated target-column rows: the v3 backfill-verification primitive (v2 verified through `eql_v2.count_encrypted_with_active_config`, which needs the config table v3 doesn't have).

### `readManifest(cwd)` / `writeManifest(manifest, cwd)`

Read/write `.cipherstash/migrations.json` — the repo-side intent declaration. Zod-validated. The manifest is optional; commands work without it but you lose the `plan` diff.

## Drop-in usage in a BullMQ/Inngest worker

```ts
import pg from 'pg'
import { runBackfill } from '@cipherstash/migrate'
import { encryptionClient, usersTable } from './src/encryption/index.js'

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })

export async function handler({ signal }: { signal: AbortSignal }) {
  const db = await pool.connect()
  try {
    return await runBackfill({
      db,
      encryptionClient,
      tableSchema: usersTable,
      tableName: 'users',
      schemaColumnKey: 'email',
      plaintextColumn: 'email',
      encryptedColumn: 'email_encrypted',
      pkColumn: 'id',
      chunkSize: 2000,
      signal,
      onProgress: (p) => console.log(`${p.rowsProcessed}/${p.rowsTotal}`),
    })
  } finally {
    db.release()
  }
}
```
