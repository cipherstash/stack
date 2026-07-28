# @cipherstash/migrate

Primitives for safely and resumably migrating existing plaintext columns to concrete EQL v3 `eql_v3_*` domains in production PostgreSQL databases.

The package backs `stash encrypt backfill` and `stash encrypt drop`. You can also embed `runBackfill()` in a worker or cron job when a large migration should not run inside a CLI process.

## Lifecycle

```text
schema-added → dual-writing → backfilling → backfilled → dropped
```

EQL v3 has no configuration table and no rename cut-over. The application switches to the encrypted column by name after backfill, then drops the original plaintext column after verifying coverage. State is tracked in the append-only `cipherstash.cs_migrations` table installed by `stash eql install`.

State readers still accept the legacy `cut_over` event and its `cut-over` phase. Manifest readers retain the `cut-over` target phase and `eqlVersion: 2`. Those fields are kept only so status tools can display existing migration history; this package no longer exports the EQL v2 Proxy configuration or rename primitives.

## API

```ts
import {
  appendEvent,
  installMigrationsSchema,
  latestByColumn,
  progress,
  readManifest,
  runBackfill,
  writeManifest,
} from '@cipherstash/migrate'
```

### `installMigrationsSchema(client)`

Creates `cipherstash.cs_migrations` idempotently. Normally called by `stash eql install`.

### `runBackfill(options)`

Runs a chunked, resumable, idempotent plaintext-to-encrypted backfill. For each chunk, it selects the next keyset page and encrypts it through `bulkEncryptModels` before `BEGIN`. The database transaction commits only the encrypted-column writes and the corresponding `cs_migrations` checkpoint. The `encrypted IS NULL` guard makes retries converge.

Pass an initialized EQL v3 `Encryption` client and an EQL v3 `encryptedTable`. The lower-level runner writes the envelope produced by the supplied client; the `stash encrypt backfill` command additionally verifies that the destination is an `eql_v3_*` domain before invoking it.

### State and manifest helpers

`appendEvent`, `progress`, and `latestByColumn` access the migration event log. `readManifest` and `writeManifest` manage the Zod-validated `.cipherstash/migrations.json` intent file.

### Domain and coverage helpers

`detectColumnEqlVersion`, `classifyEqlDomain`, `listEncryptedColumns`, and `resolveEncryptedColumn` recognize concrete EQL v3 domains and resolve the encrypted counterpart without relying on a naming convention. A legacy `eql_v2_encrypted` column returns `null`; callers must not treat that as an authorable generation.

`countUnencrypted(client, table, plaintextColumn, encryptedColumn)` counts rows with plaintext set and ciphertext NULL. `stash encrypt drop` uses it before generating the v3 plaintext-drop migration. `countEncrypted` counts populated target rows. Both are full-table scans intended for one-shot verification.

## Worker example

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
      schemaColumnKey: 'email_encrypted',
      plaintextColumn: 'email',
      encryptedColumn: 'email_encrypted',
      pkColumn: 'id',
      chunkSize: 2000,
      signal,
    })
  } finally {
    db.release()
  }
}
```
