# @cipherstash/migrate

Primitives for migrating existing plaintext columns to CipherStash's `eql_v2_encrypted` in production Postgres databases, safely and resumably.

Backs the `stash encrypt` CLI command group, but also exported for direct use — embed `runBackfill()` in your own worker or cron job when you'd rather not pipe gigabytes through a CLI process.

## Lifecycle

Each column walks through these phases:

```
schema-added → dual-writing → backfilling → backfilled → cut-over → dropped
```

State is tracked in an append-only `cipherstash.cs_migrations` table installed by `stash db install`. The EQL intent (which indexes, which cast_as) continues to live in `eql_v2_configuration` so Proxy continues to work against the same database.

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

Creates `cipherstash.cs_migrations` idempotently. Normally called by `stash db install`.

### `runBackfill({ db, encryptionClient, tableSchema, tableName, plaintextColumn, encryptedColumn, pkColumn, schemaColumnKey, chunkSize?, signal?, onProgress? })`

Chunked, resumable, idempotent backfill of plaintext → encrypted. Per chunk, in a single transaction: select next page → encrypt via `client.bulkEncryptModels` → `UPDATE … FROM (VALUES …)` → `INSERT` a `backfill_checkpoint` event. Guards with `encrypted IS NULL` so re-runs never double-write.

- `db`: a `pg.PoolClient` (the runner drives transactions on it).
- `encryptionClient`: your initialised `@cipherstash/stack` `EncryptionClient` (or anything that exposes `bulkEncryptModels(models, table)` returning `{ data } | { failure }`).
- `tableSchema`: the `EncryptedTable` for the target table from your encryption client file.
- `signal`: optional `AbortSignal`. If aborted between chunks, the backfill exits cleanly and leaves a resumable checkpoint.

Returns `{ resumed, rowsProcessed, rowsTotal, completed }`.

### `appendEvent(client, { tableName, columnName, event, phase, … })` / `progress(client, table, column)` / `latestByColumn(client)`

Direct access to the `cs_migrations` event log. Use these if you're building your own migration UI or orchestration on top.

### `renameEncryptedColumns(client)` / `reloadConfig(client)`

Thin wrappers around `eql_v2.rename_encrypted_columns()` (the cut-over primitive) and `eql_v2.reload_config()` (Proxy refresh hint — no-op when connected directly to Postgres).

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
