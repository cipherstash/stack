import { isEncryptedPayload } from '@cipherstash/stack'
import type { ClientBase, PoolClient } from 'pg'
import {
  countUnencrypted,
  fetchUnencryptedPage,
  qualifyTable,
} from './cursor.js'
import { quoteIdent } from './sql.js'
import { type MigrationPhase, appendEvent, progress } from './state.js'

// Loose structural types — keep this library decoupled from @cipherstash/stack
// so @cipherstash/migrate can be built and tested without pulling the full
// stack graph in. `EncryptionClientLike` matches the shape `EncryptionClient`
// from `@cipherstash/stack/encryption` exposes via `bulkEncryptModels`.

/**
 * Shape returned by {@link EncryptionClientLike.bulkEncryptModels} on success.
 * `data` is the array of models with the configured fields replaced by
 * ciphertext payloads, preserving `__pk` and any other non-encrypted fields.
 */
export interface BulkEncryptResultSuccess<T> {
  failure?: undefined
  data: T[]
}

/**
 * Shape returned by {@link EncryptionClientLike.bulkEncryptModels} on failure.
 * Matches `@byteslice/result`'s `{ failure: { message } }` convention used
 * by `@cipherstash/stack`. The backfill halts and writes an `error` event
 * to `cs_migrations` when this is returned.
 */
export interface BulkEncryptResultFailure {
  failure: { message: string; type?: string }
  data?: undefined
}

/**
 * Discriminated union returned by bulk-encrypt. Narrow with `if (r.failure)`
 * vs `if (r.data)`. No exceptions are thrown by the underlying operation.
 */
export type BulkEncryptResult<T> =
  | BulkEncryptResultSuccess<T>
  | BulkEncryptResultFailure

/**
 * A thenable wrapper around {@link BulkEncryptResult}. `@cipherstash/stack`'s
 * `bulkEncryptModels` returns a fluent operation builder that resolves to a
 * `Result` when awaited; this alias accepts anything `PromiseLike` so we
 * don't bind to the full operation class in type-land.
 */
export type BulkEncryptThenable<T> = PromiseLike<BulkEncryptResult<T>>

/**
 * Minimal surface of `@cipherstash/stack`'s `EncryptionClient` used by
 * {@link runBackfill}. Only `bulkEncryptModels` is required — the backfill
 * encrypts in batches, it does not need the single-value `encrypt` API.
 *
 * Supplying an object that duck-types to this interface is enough; you do
 * not have to import `EncryptionClient` itself.
 *
 * @example
 * ```ts
 * // Typical wiring: the user's `src/encryption/index.ts` exports an
 * // already-initialised client, and you pass it through.
 * import { encryptionClient } from './src/encryption/index.js'
 * await runBackfill({ encryptionClient, ... })
 * ```
 */
export interface EncryptionClientLike {
  /**
   * Bulk-encrypt a batch of plaintext models against a table schema.
   *
   * @param input - Array of models. Each row is `{ [schemaColumnKey]: plaintext, ... }`.
   *   The backfill also includes a `__pk` field per row so it can correlate
   *   the encrypted result back to the database row on UPDATE.
   * @param table - The `EncryptedTable` schema for the target table. Typed
   *   as `any` here to keep this library decoupled from `@cipherstash/stack`.
   */
  bulkEncryptModels(
    input: Array<Record<string, unknown>>,
    // biome-ignore lint/suspicious/noExplicitAny: Stack's EncryptedTable is generic
    table: any,
  ): BulkEncryptThenable<Record<string, unknown>>
}

/**
 * Snapshot of backfill progress, passed to {@link BackfillOptions.onProgress}
 * after every successful chunk commit. Values represent the cumulative state
 * *after* the most recent chunk — including any rows processed by a prior
 * run that this invocation resumed from.
 */
export interface BackfillProgress {
  /** Total rows written to the encrypted column so far (includes a resumed prior run). */
  rowsProcessed: number
  /** Total rows we expect to process over the life of this migration (incl. resumed). */
  rowsTotal: number
  /** PK of the last row processed in the most recent chunk, cast to text. */
  lastPk: string | null
  /** Chunk size used for this run (echoed from {@link BackfillOptions.chunkSize}). */
  chunkSize: number
  /** Zero-based index of the chunk that just completed. */
  chunkIndex: number
}

/**
 * Options for {@link runBackfill}.
 *
 * Distinguishes three separate name spaces that a reader has to keep straight:
 * - **Physical names** ({@link tableName}, {@link plaintextColumn}, {@link encryptedColumn}, {@link pkColumn})
 *   are Postgres identifiers used verbatim in SQL.
 * - **Schema name** ({@link schemaColumnKey}) is the key on the `EncryptedTable`
 *   schema object that corresponds to the column. In the common drizzle
 *   convention — where the schema declares the encrypted column (not the
 *   plaintext one) — this equals `encryptedColumn`. Pass explicitly only
 *   when your schema's object keys diverge from the physical column names.
 */
export interface BackfillOptions {
  /**
   * A pg pool client the runner owns for the duration of the call. The
   * runner issues `BEGIN`/`COMMIT` on this connection for each chunk, so it
   * must not be shared across concurrent work during the backfill.
   *
   * Acquire with `const db = await pool.connect()`, release with
   * `db.release()` in your `finally`.
   */
  db: PoolClient
  /**
   * Initialised encryption client. See {@link EncryptionClientLike} for the
   * required surface (just `bulkEncryptModels`).
   */
  encryptionClient: EncryptionClientLike
  /**
   * The `EncryptedTable` schema object for the target table, as exported
   * from the user's `src/encryption/index.ts`. Passed through to
   * `encryptionClient.bulkEncryptModels(models, tableSchema)`. Typed as
   * `any` to avoid coupling this library to `@cipherstash/stack`.
   */
  // biome-ignore lint/suspicious/noExplicitAny: Stack's EncryptedTable is generic
  tableSchema: any
  /**
   * Physical Postgres table name. Supports `"schema.table"` for non-default
   * schemas (identifiers are quoted automatically).
   */
  tableName: string
  /**
   * The key in {@link tableSchema} that corresponds to this column. With
   * the drizzle `extractEncryptionSchema` convention, where the schema is
   * derived from a table like `{ email_encrypted: encryptedType(...) }`,
   * this equals {@link encryptedColumn}. With a handwritten
   * `encryptedTable('users', { email: … })` schema where there's only one
   * column, this usually equals {@link plaintextColumn}.
   */
  schemaColumnKey: string
  /**
   * Physical column that holds the plaintext being encrypted, e.g. `email`.
   * The runner reads rows where this is `NOT NULL` and the target encrypted
   * column is `NULL`.
   */
  plaintextColumn: string
  /**
   * Physical column that receives the `eql_v2_encrypted` ciphertext JSON,
   * e.g. `email_encrypted`. Must already exist (typically created by
   * `drizzle-kit` / a prior migration) before backfill starts.
   */
  encryptedColumn: string
  /**
   * Physical single-column primary key used for keyset pagination — the
   * runner issues `WHERE pk > $after ORDER BY pk ASC LIMIT $n`. Must be
   * comparable with `>` (bigint, integer, text, uuid all work). Composite
   * primary keys are not yet supported.
   */
  pkColumn: string
  /**
   * Rows per chunk / transaction. Default 1000. Tune down if you see lock
   * contention, up for tables with small row payloads. A single chunk is
   * one `BEGIN`/`UPDATE`/`INSERT checkpoint`/`COMMIT` cycle, so the value
   * also bounds how much work is lost when you `Ctrl-C` mid-chunk.
   */
  chunkSize?: number
  /**
   * Optional abort signal. Checked *between* chunks — the in-flight chunk
   * always completes and checkpoints before the loop exits. Safe to wire
   * to `SIGINT` / `SIGTERM`; the CLI does exactly this.
   */
  signal?: AbortSignal
  /**
   * Invoked synchronously after each chunk has committed. Safe for logging
   * and UI updates; throwing from this callback will kill the backfill.
   */
  onProgress?: (progress: BackfillProgress) => void
  /**
   * Optional coercion applied to each row's plaintext value before it is
   * passed to {@link EncryptionClientLike.bulkEncryptModels}. Needed when
   * the pg driver's native JS type doesn't match the schema's declared
   * dataType — e.g. pg returns `numeric` as a string, but a schema
   * declaring `dataType('number')` expects a JS number. The CLI
   * builds an appropriate coercer from the schema's `cast_as`; library
   * callers can supply their own or leave undefined (identity).
   */
  transformPlaintext?: (value: unknown) => unknown
}

/**
 * Return value from {@link runBackfill}.
 */
export interface BackfillResult {
  /**
   * `true` if the run began from a previously-recorded checkpoint rather
   * than starting fresh. Determined by the most recent event for this
   * column being a `backfill_checkpoint`.
   */
  resumed: boolean
  /**
   * Cumulative rows written to the encrypted column, including any from a
   * prior run this invocation resumed from.
   */
  rowsProcessed: number
  /**
   * Total rows the migration expects to process end-to-end (including
   * resumed). Computed as `priorProcessed + currentRunTotal` at start.
   */
  rowsTotal: number
  /**
   * `true` if this run drained all remaining rows. `false` means the run
   * was aborted (via {@link BackfillOptions.signal}) or is otherwise
   * paused and should be resumed by re-invoking with the same options.
   */
  completed: boolean
}

/**
 * Run a chunked, resumable, idempotent backfill of plaintext → encrypted.
 *
 * Per chunk, in a single transaction:
 *   1. `SELECT` the next page of rows where the encrypted column is `NULL`
 *      and the PK is greater than the cursor.
 *   2. Encrypt the batch via {@link EncryptionClientLike.bulkEncryptModels}.
 *   3. `UPDATE … FROM (VALUES …)` to write the ciphertext back.
 *   4. `INSERT` a `backfill_checkpoint` event into `cipherstash.cs_migrations`.
 *   5. `COMMIT`.
 *
 * **Idempotency** — the `encrypted IS NULL` guard in both the SELECT and the
 * UPDATE's `WHERE` clause means re-runs never double-write a row, even if
 * the cursor is lost.
 *
 * **Resumability** — restarting with the same arguments will pick up from
 * the last committed checkpoint. Use {@link BackfillOptions.signal} to
 * abort cleanly on `SIGINT`.
 *
 * **Failure handling** — if any chunk fails (encrypt error or DB error),
 * the transaction is rolled back, an `error` event is appended to
 * `cs_migrations` for diagnostics, and the error is re-thrown.
 *
 * @example
 * ```ts
 * const db = await pool.connect()
 * try {
 *   const result = await runBackfill({
 *     db,
 *     encryptionClient,
 *     tableSchema: usersTable,
 *     tableName: 'users',
 *     schemaColumnKey: 'email',
 *     plaintextColumn: 'email',
 *     encryptedColumn: 'email_encrypted',
 *     pkColumn: 'id',
 *     chunkSize: 1000,
 *     onProgress: (p) => console.log(`${p.rowsProcessed}/${p.rowsTotal}`),
 *   })
 *   console.log(result.completed ? 'done' : 'paused — re-run to resume')
 * } finally {
 *   db.release()
 * }
 * ```
 */
export async function runBackfill(
  options: BackfillOptions,
): Promise<BackfillResult> {
  const chunkSize = options.chunkSize ?? 1000
  const { db, tableName, pkColumn, plaintextColumn, encryptedColumn } = options

  const rowsTotal = await countUnencrypted(
    db,
    tableName,
    plaintextColumn,
    encryptedColumn,
  )

  const last = await progress(db, tableName, plaintextColumn)
  const resumeCursor =
    last?.event === 'backfill_checkpoint' ? last.cursorValue : null
  const resumed = resumeCursor !== null
  const priorProcessed =
    last?.event === 'backfill_checkpoint' ? (last.rowsProcessed ?? 0) : 0

  await appendEvent(db, {
    tableName,
    columnName: plaintextColumn,
    event: 'backfill_started',
    phase: 'backfilling',
    cursorValue: resumeCursor,
    rowsProcessed: priorProcessed,
    rowsTotal: priorProcessed + rowsTotal,
    details: { chunkSize, resumed },
  })

  let cursor = resumeCursor
  let rowsProcessed = priorProcessed
  const rowsTotalWithResumed = priorProcessed + rowsTotal
  let chunkIndex = 0
  let completed = false

  try {
    while (true) {
      if (options.signal?.aborted) break

      const page = await fetchUnencryptedPage(db, {
        tableName,
        pkColumn,
        plaintextColumn,
        encryptedColumn,
        after: cursor,
        limit: chunkSize,
      })

      if (page.rows.length === 0) {
        completed = true
        break
      }

      const coerce = options.transformPlaintext ?? ((v: unknown) => v)
      const models = page.rows.map((row) => ({
        __pk: row.pk,
        [options.schemaColumnKey]: coerce(row.plaintext),
      }))

      const encryptResult = await options.encryptionClient.bulkEncryptModels(
        models,
        options.tableSchema,
      )

      if (encryptResult.failure) {
        throw new Error(
          `bulkEncryptModels failed: ${encryptResult.failure.message}`,
        )
      }

      // Leak guard: every row's schemaColumnKey field must be a valid EQL
      // payload ({ v, i, c|sv, … }). If any row comes back as a primitive
      // or a mis-shaped object, the encryption client silently passed the
      // plaintext through — typically because the schema is keyed by a
      // different name than `schemaColumnKey`. Fail loudly before any
      // write commits; this is what prevents `(82.60)`-shaped composite
      // values from ending up in the encrypted column.
      for (const [i, row] of encryptResult.data.entries()) {
        const value = row[options.schemaColumnKey]
        if (!isEncryptedPayload(value)) {
          const pk = row.__pk ?? page.rows[i]?.pk
          const preview = JSON.stringify(value)?.slice(0, 120) ?? String(value)
          throw new Error(
            `Encryption client returned a non-ciphertext value at model key "${options.schemaColumnKey}" for pk=${pk} (got: ${preview}). This usually means the schema column key does not match your EncryptedTable. Verify that your schema declares a column keyed "${options.schemaColumnKey}", or pass --schema-column-key <name> to override.`,
          )
        }
      }

      await db.query('BEGIN')
      try {
        await writeEncryptedChunk(db, {
          tableName,
          pkColumn,
          encryptedColumn,
          schemaColumnKey: options.schemaColumnKey,
          encryptedRows: encryptResult.data,
        })
        rowsProcessed += page.rows.length
        cursor = page.lastPk
        await appendEvent(db, {
          tableName,
          columnName: plaintextColumn,
          event: 'backfill_checkpoint',
          phase: 'backfilling',
          cursorValue: cursor,
          rowsProcessed,
          rowsTotal: rowsTotalWithResumed,
          details: { chunkIndex, chunkRows: page.rows.length },
        })
        await db.query('COMMIT')
      } catch (err) {
        await db.query('ROLLBACK').catch(() => {})
        throw err
      }

      options.onProgress?.({
        rowsProcessed,
        rowsTotal: rowsTotalWithResumed,
        lastPk: cursor,
        chunkSize,
        chunkIndex,
      })
      chunkIndex += 1
    }

    if (completed) {
      await appendEvent(db, {
        tableName,
        columnName: plaintextColumn,
        event: 'backfilled',
        phase: 'backfilled',
        cursorValue: cursor,
        rowsProcessed,
        rowsTotal: rowsTotalWithResumed,
        details: { chunkCount: chunkIndex },
      })
    }
  } catch (err) {
    await appendEvent(db, {
      tableName,
      columnName: plaintextColumn,
      event: 'error',
      phase: 'backfilling',
      cursorValue: cursor,
      rowsProcessed,
      rowsTotal: rowsTotalWithResumed,
      details: {
        message: err instanceof Error ? err.message : String(err),
        chunkIndex,
      },
    })
    throw err
  }

  return {
    resumed,
    rowsProcessed,
    rowsTotal: rowsTotalWithResumed,
    completed,
  }
}

interface WriteChunkOptions {
  tableName: string
  pkColumn: string
  encryptedColumn: string
  schemaColumnKey: string
  encryptedRows: Array<Record<string, unknown>>
}

async function writeEncryptedChunk(
  db: ClientBase,
  opts: WriteChunkOptions,
): Promise<void> {
  if (opts.encryptedRows.length === 0) return

  const table = qualifyTable(opts.tableName)
  const pk = quoteIdent(opts.pkColumn)
  const enc = quoteIdent(opts.encryptedColumn)

  const params: unknown[] = []
  const valuesSql = opts.encryptedRows
    .map((row) => {
      const pkValue = row.__pk
      const encryptedValue = row[opts.schemaColumnKey]
      params.push(pkValue)
      const pkParam = `$${params.length}`
      params.push(encryptedValue)
      const encParam = `$${params.length}::jsonb`
      return `(${pkParam}, ${encParam})`
    })
    .join(', ')

  const sql = `
    UPDATE ${table} AS t
    SET ${enc} = v.enc
    FROM (VALUES ${valuesSql}) AS v(pk, enc)
    WHERE t.${pk}::text = v.pk::text AND t.${enc} IS NULL
  `

  await db.query(sql, params)
}
