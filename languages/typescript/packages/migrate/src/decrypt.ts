import { isEncryptedPayload } from '@cipherstash/stack'
import type { ClientBase, PoolClient } from 'pg'
import type { ForcedBy } from './column-migration.js'
import {
  countUndecrypted,
  fetchUndecryptedPage,
  qualifyTable,
} from './cursor.js'
import { type ChunkedRunProgress, runChunkedMigration } from './engine.js'
import { quoteIdent } from './sql.js'

/**
 * One position-stable entry of a bulk-decrypt result: the plaintext, or a
 * per-row failure. Structural, so this package stays decoupled from
 * `@cipherstash/stack`'s generics — `EncryptionClient.bulkDecrypt` resolves to
 * exactly this shape (`{ data } | { error, code?, … }`).
 */
export type BulkDecryptItem =
  | { id?: string; data: unknown; error?: undefined }
  | { id?: string; error: unknown; code?: unknown; data?: undefined }

/** Whole-call result of a bulk decrypt (`@byteslice/result` convention). */
export type BulkDecryptResult =
  | { failure?: undefined; data: BulkDecryptItem[] }
  | { failure: { message: string }; data?: undefined }

/**
 * Minimal surface of `@cipherstash/stack`'s `EncryptionClient` the reverse
 * backfill needs: `bulkDecrypt`, which decrypts a whole chunk in ONE ZeroKMS
 * round trip and reports failures per row instead of failing the batch.
 *
 * Per-row failure is the property this runner depends on. A value bound to an
 * end-user lock context can only be decrypted as that user; with workspace
 * credentials it fails on its own, and the rest of the chunk still decrypts.
 * `bulkDecryptModels` fails the whole chunk instead, which would turn one
 * locked value into a stalled migration.
 *
 * Declared with method syntax deliberately: method parameters are checked
 * bivariantly, so the SDK's narrower `Encrypted` payload type is accepted
 * without a cast.
 */
export interface DecryptionClientLike {
  bulkDecrypt(
    payloads: Array<{ id?: string; data: Record<string, unknown> | null }>,
  ): PromiseLike<BulkDecryptResult>
}

/**
 * Thrown when the first chunk of a run decrypts NOTHING. Its message is
 * author-controlled and carries only counts and error codes — never a value —
 * so the CLI prints it verbatim.
 *
 * A whole chunk failing is almost never "every one of these rows happens to
 * be lock-context bound". It is credentials resolving to a different
 * workspace or keyset, and carrying on would spend one ZeroKMS request per
 * chunk across the entire table to decrypt nothing. The run stops before
 * writing that chunk and records an `error` event carrying the last committed
 * cursor, so fixing the credentials and re-running resumes from the last
 * checkpoint rather than from the first primary key.
 */
export class UndecryptableBatchError extends Error {
  constructor(
    readonly rows: number,
    readonly codes: Readonly<Record<string, number>>,
  ) {
    super(
      `None of the ${rows} row(s) in the first batch could be decrypted (${formatCodes(codes)}). Nothing was written. This usually means the credentials in this shell resolve to a different workspace or keyset than the one that encrypted the data — export the CS_* values of the environment that wrote it and re-run. If these rows really are undecryptable with workspace credentials — values bound to an end-user lock context, or rows an earlier run already skipped — re-run with --continue-on-undecryptable to record them as skipped and carry on.`,
    )
    this.name = 'UndecryptableBatchError'
  }
}

/**
 * Thrown when the chunk's `UPDATE` fails — most often a decrypted value that
 * does not cast to the plaintext column's declared type.
 *
 * Postgres puts the offending INPUT in the text of a cast error
 * (`invalid input syntax for type integer: "…"`), and on this path the input
 * is decrypted plaintext. The engine's `error` event stores only the error's
 * name and the safe details this direction supplies, never a message, and
 * this error must not carry the database's message either. It carries only the SQLSTATE, the constraint name when there is
 * one, and the column and type names; the original error is deliberately not
 * kept as `cause`.
 */
export class PlaintextWriteError extends Error {
  constructor(
    readonly sqlState: string | undefined,
    readonly plaintextColumn: string,
    readonly plaintextSqlType: string,
    readonly constraint: string | undefined,
  ) {
    super(
      `Could not write decrypted values into "${plaintextColumn}" (${plaintextSqlType})${sqlState ? `: SQLSTATE ${sqlState}` : ''}${constraint ? `, constraint "${constraint}"` : ''}. Nothing from this chunk was written. ${sqlState?.startsWith('22') ? `A decrypted value does not fit the column's type; widen "${plaintextColumn}" (for example to the type \`stash decrypt plan\` suggests) and re-run.` : 'Check the column and re-run; the database message is withheld because it can contain row data.'}`,
    )
    this.name = 'PlaintextWriteError'
  }
}

/**
 * The largest chunk one write can carry. Each decrypted row binds TWO
 * parameters in the chunk's `UPDATE … FROM (VALUES ($1, $2), …)` (the primary
 * key, and the value packed with the ciphertext it was decrypted from), and
 * Postgres's wire protocol caps a statement at 65535 parameters, so 32767
 * rows is the most that can ever be written in one statement. A larger chunk
 * would fail only after its ZeroKMS request.
 */
export const MAX_DECRYPT_CHUNK_SIZE = Math.floor(65535 / 2)

/** Options for {@link runDecryptBackfill}. Mirrors {@link BackfillOptions}. */
export interface DecryptBackfillOptions {
  /** A pool client the runner owns for the call (`BEGIN`/`COMMIT` per chunk). */
  db: PoolClient
  /** Initialised encryption client; only `bulkDecrypt` is used. */
  decryptionClient: DecryptionClientLike
  /** Physical table name; `schema.table` supported. */
  tableName: string
  /** The EQL v3 column to read ciphertext from. Events are keyed by it. */
  encryptedColumn: string
  /** The plaintext column to fill. Must already exist (`stash decrypt plan`). */
  plaintextColumn: string
  /**
   * The plaintext column's declared type, as `format_type` renders it (see
   * `columnSqlType`). Every decrypted value is cast to it on write, so the
   * twin's real type is honoured, and JSON targets (`json`/`jsonb`) are
   * serialised as JSON documents rather than as scalars.
   */
  plaintextSqlType: string
  /** Single-column primary key for keyset pagination. */
  pkColumn: string
  /**
   * Rows per chunk, which is also the size of each `bulkDecrypt` call — one
   * ZeroKMS request per chunk. Default `500`. A whole number from 1 to
   * {@link MAX_DECRYPT_CHUNK_SIZE}; anything else throws a `RangeError`
   * before any event is recorded or any request is made.
   */
  chunkSize?: number
  /** Checked between chunks; the in-flight chunk always commits first. */
  signal?: AbortSignal
  onProgress?: (progress: DecryptBackfillProgress) => void
  /**
   * Re-decrypt every row with ciphertext, including rows whose plaintext is
   * already set, and overwrite that plaintext. Recovery path for drift (the
   * application updated the ciphertext without writing the plaintext twin),
   * and the way to replace plaintext that predates the reverse lifecycle.
   *
   * Safe only while dual-writes are live. It writes the decrypted ciphertext
   * over whatever the plaintext column holds, so any row the application
   * wrote to the plaintext column alone (a newer value, or a value cleared on
   * purpose) gets the older ciphertext's value back.
   *
   * The column migration can force a run this does not: while a forced pass
   * is owed (see {@link ColumnMigration}), every run is one, and
   * {@link DecryptBackfillResult.forcedBy} says why.
   */
  force?: boolean
  /**
   * Carry on when the first chunk of a run decrypts nothing, instead of
   * throwing {@link UndecryptableBatchError}. For a table whose first rows by
   * primary key genuinely are all lock-context bound, or a re-run where only
   * previously skipped rows remain. Off by default because the far likelier
   * cause is credentials for the wrong workspace or keyset.
   */
  continueOnUndecryptable?: boolean
}

/** Progress after each committed chunk. */
export interface DecryptBackfillProgress {
  /** Rows visited so far, decrypted or skipped (includes a resumed run). */
  rowsProcessed: number
  rowsTotal: number
  /** Cumulative rows that could not be decrypted and were left NULL. */
  rowsSkipped: number
  lastPk: string | null
  chunkSize: number
  chunkIndex: number
}

/** Result of {@link runDecryptBackfill}. */
export interface DecryptBackfillResult {
  resumed: boolean
  /** Rows visited, decrypted or skipped. */
  rowsProcessed: number
  rowsTotal: number
  /** Rows written with plaintext. `rowsProcessed - rowsSkipped`. */
  rowsDecrypted: number
  /**
   * Rows whose ciphertext could not be decrypted with these credentials and
   * whose plaintext was therefore left NULL — typically values bound to an
   * end-user lock context. Cumulative across a resumed run.
   */
  rowsSkipped: number
  /** Skips in THIS run, by error code (`UNKNOWN` when the row carried none). */
  skippedByCode: Record<string, number>
  /**
   * Primary keys (first {@link NULL_PLAINTEXT_SAMPLE_SIZE}, this run) of rows
   * whose ciphertext decrypted to `null` for a non-JSON column — the
   * `NULL_PLAINTEXT` skips. They are not a credentials problem, so they need
   * a different remedy, and naming them is what makes it actionable. Keys
   * only; never values.
   */
  nullPlaintextPks: string[]
  completed: boolean
  /** Whether this run was a forced pass. */
  force: boolean
  /**
   * Why: `caller` (`force` was passed), `forced-pass` (an earlier forced pass
   * had not completed), `existing-values` (the plaintext column held values
   * before the column migration began, with no waiver recorded), or `null`
   * when unforced.
   */
  forcedBy: ForcedBy
}

/** How many `NULL_PLAINTEXT` primary keys a result carries. */
export const NULL_PLAINTEXT_SAMPLE_SIZE = 20

/**
 * Run a chunked, resumable, idempotent backfill of ciphertext → plaintext —
 * the reverse of {@link runBackfill}, on the same engine.
 *
 * Per chunk: select the next keyset page where the encrypted column is set and
 * the plaintext column is NULL; decrypt it with ONE `bulkDecrypt` call; then
 * in a single transaction write the plaintext for every row that decrypted
 * and append a `decrypt_checkpoint` event.
 *
 * **Rows that cannot be decrypted are skipped, not fatal.** Their plaintext
 * stays NULL, the cursor moves past them, and they are counted
 * (`rowsSkipped`, plus per-code tallies in the event details). The common
 * cause is a value bound to an end-user lock context, which only that user
 * can decrypt; there is deliberately no bypass. Because the skipped rows keep
 * a NULL plaintext, {@link countUndecrypted} still counts them, so the
 * coverage gate in `stash decrypt drop` refuses to drop the only copy of
 * their data. Under `force` the plaintext column may hold a stale value, so a
 * forced pass sets a skipped row's plaintext to NULL rather than leave it,
 * including a value the application wrote after decrypting the row as its
 * user: it cannot tell that from a stale one, so per-user remediation
 * belongs after the last forced pass.
 * A later run (after the cursor-based pass has completed) starts
 * from the beginning and retries them.
 *
 * **Leak guard (reverse).** A decrypted value that is itself an EQL envelope
 * means the client handed ciphertext back unchanged; writing it would put
 * ciphertext in the plaintext column. The run fails before the chunk commits.
 *
 * Events are recorded under `(tableName, encryptedColumn)` with
 * `details.plaintextColumn` on every event, so later commands recover the
 * pairing from state alone.
 *
 * **Resume and obligations.** A run resumes from its last checkpoint, and
 * also from an `error` event, which records the last committed cursor; a
 * failed run does not throw away the progress before it. Whether the run is
 * forced is decided by the column migration ({@link ColumnMigration}), not
 * only by `force`: a forced pass, once started, is owed until one completes,
 * and so is one over a plaintext column that held values before the column
 * migration began (unless a waiver was recorded with
 * {@link ColumnMigration.confirmDualWrites}). A `force` run over an unforced
 * pass starts from the first row.
 *
 * **Refused** while a forward column migration of `plaintextColumn` into
 * this column is still open, and when `plaintextColumn` is not the column the
 * column migration in progress recorded.
 *
 * **Write errors.** A failed chunk write throws {@link PlaintextWriteError},
 * never the database's own message, which can contain the decrypted value.
 */
export async function runDecryptBackfill(
  options: DecryptBackfillOptions,
): Promise<DecryptBackfillResult> {
  const chunkSize = options.chunkSize ?? 500
  if (
    !Number.isSafeInteger(chunkSize) ||
    chunkSize < 1 ||
    chunkSize > MAX_DECRYPT_CHUNK_SIZE
  ) {
    throw new RangeError(
      `chunkSize must be a whole number from 1 to ${MAX_DECRYPT_CHUNK_SIZE} (got ${String(chunkSize)}).`,
    )
  }
  const {
    db,
    tableName,
    pkColumn,
    encryptedColumn,
    plaintextColumn,
    plaintextSqlType,
  } = options
  const serialize = plaintextSerializer(plaintextSqlType)
  const skippedByCode: Record<string, number> = {}
  const nullPlaintextPks: string[] = []

  const result = await runChunkedMigration({
    db,
    tableName,
    stateColumn: encryptedColumn,
    twinColumn: plaintextColumn,
    direction: 'reverse',
    chunkSize,
    signal: options.signal,
    force: options.force,
    baseDetails: { plaintextColumn },
    errorDetails: safeErrorDetails,
    countPending: (after, { force }) =>
      countUndecrypted(
        db,
        tableName,
        encryptedColumn,
        plaintextColumn,
        force,
        after === null ? null : { pkColumn, pk: after },
      ),
    fetchPage: (after, limit, { force }) =>
      fetchUndecryptedPage(db, {
        tableName,
        pkColumn,
        encryptedColumn,
        plaintextColumn,
        after,
        limit,
        force,
      }),
    prepareChunk: async (rows, { chunkIndex, force }) => {
      const payloads = rows.map((row) => ({
        id: row.pk,
        data: asPayload(row.ciphertext),
      }))
      const decrypted = await options.decryptionClient.bulkDecrypt(payloads)
      if (decrypted.failure) {
        throw new Error(`bulkDecrypt failed: ${decrypted.failure.message}`)
      }
      if (decrypted.data.length !== rows.length) {
        throw new Error(
          `bulkDecrypt returned ${decrypted.data.length} result(s) for ${rows.length} payload(s); refusing to correlate a short or long result positionally.`,
        )
      }

      const writes: DecryptedWrite[] = []
      const chunkCodes: Record<string, number> = {}
      let skipped = 0
      // A skipped row keeps whatever its plaintext column holds. Unforced,
      // that is NULL, which `countUndecrypted` and the drop's coverage check
      // count. Under `force` it can be a stale value, which neither would
      // count, and the completed forced pass closes the obligation, so the
      // drop would destroy the only current copy. A forced pass writes NULL
      // over a skipped row instead (still guarded on its ciphertext).
      const skip = (pk: string, ciphertext: unknown) => {
        skipped++
        if (force) writes.push({ pk, value: null, ciphertext })
      }
      // Rows that decrypted, whether or not they produced a write. A row
      // decrypting to `null` (NULL_PLAINTEXT) proves the credentials work.
      let decryptedCount = 0
      for (const [i, item] of decrypted.data.entries()) {
        const { pk } = rows[i]
        if (item.error !== undefined) {
          tally(chunkCodes, codeOf(item))
          skip(pk, rows[i].ciphertext)
          continue
        }
        if (isEncryptedPayload(item.data)) {
          // Only the pk goes into the message — the value is ciphertext, but
          // nothing about this path should normalise putting row data in an
          // exception.
          throw new Error(
            `Decryption client returned an EQL envelope instead of plaintext for pk=${pk}. Refusing to write ciphertext into the plaintext column "${plaintextColumn}".`,
          )
        }
        decryptedCount++
        const value = serialize(item.data)
        if (value === undefined) {
          tally(chunkCodes, 'NULL_PLAINTEXT')
          if (nullPlaintextPks.length < NULL_PLAINTEXT_SAMPLE_SIZE) {
            nullPlaintextPks.push(pk)
          }
          skip(pk, rows[i].ciphertext)
          continue
        }
        // The ciphertext as read, so the write can refuse a row whose
        // ciphertext changed while this chunk was being decrypted.
        writes.push({ pk, value, ciphertext: rows[i].ciphertext })
      }

      // The first chunk of a run decrypting nothing is a credentials problem,
      // not a column of locked values — see UndecryptableBatchError.
      if (
        decryptedCount === 0 &&
        chunkIndex === 0 &&
        !options.continueOnUndecryptable
      ) {
        throw new UndecryptableBatchError(rows.length, chunkCodes)
      }

      for (const [code, count] of Object.entries(chunkCodes)) {
        skippedByCode[code] = (skippedByCode[code] ?? 0) + count
      }

      return {
        skipped,
        checkpointDetails:
          skipped > 0 ? { chunkSkippedByCode: chunkCodes } : undefined,
        write: (client) =>
          writeDecryptedChunk(client, {
            tableName,
            pkColumn,
            encryptedColumn,
            plaintextColumn,
            plaintextSqlType,
            writes,
            force,
          }),
      }
    },
    onProgress: options.onProgress
      ? (progress: ChunkedRunProgress) =>
          options.onProgress?.({
            rowsProcessed: progress.rowsProcessed,
            rowsTotal: progress.rowsTotal,
            rowsSkipped: progress.rowsSkipped,
            lastPk: progress.lastPk,
            chunkSize: progress.chunkSize,
            chunkIndex: progress.chunkIndex,
          })
      : undefined,
  })

  return {
    resumed: result.resumed,
    rowsProcessed: result.rowsProcessed,
    rowsTotal: result.rowsTotal,
    rowsDecrypted: result.rowsProcessed - result.rowsSkipped,
    rowsSkipped: result.rowsSkipped,
    skippedByCode,
    nullPlaintextPks,
    completed: result.completed,
    force: result.force,
    forcedBy: result.forcedBy,
  }
}

/**
 * What the `error` event may store about this direction's own failures:
 * names, codes and counts, never a value or a database message.
 */
function safeErrorDetails(error: unknown): Record<string, unknown> | undefined {
  if (error instanceof PlaintextWriteError) {
    return {
      sqlState: error.sqlState ?? null,
      constraint: error.constraint ?? null,
      plaintextSqlType: error.plaintextSqlType,
    }
  }
  if (error instanceof UndecryptableBatchError) {
    return { batchRows: error.rows, batchCodes: { ...error.codes } }
  }
  return undefined
}

/**
 * The ciphertext as read from the row, narrowed to the object shape
 * `bulkDecrypt` takes. The page query guarantees non-NULL and the column's
 * EQL domain CHECK guarantees an object; anything else is a corrupt row, and
 * handing it to the client as-is lets it be reported per row like any other
 * undecryptable value rather than crashing the chunk here.
 */
function asPayload(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object'
    ? (value as Record<string, unknown>)
    : null
}

/** A per-row failure's error code, or `UNKNOWN` when it carried none. */
function codeOf(item: { code?: unknown }): string {
  return typeof item.code === 'string' && /^[A-Z0-9_]+$/.test(item.code)
    ? item.code
    : 'UNKNOWN'
}

function tally(counts: Record<string, number>, code: string): void {
  counts[code] = (counts[code] ?? 0) + 1
}

/** `3 × UNKNOWN, 1 × INVALID_CIPHERTEXT` — stable order, for messages. */
export function formatCodes(codes: Readonly<Record<string, number>>): string {
  const entries = Object.entries(codes).sort(
    ([a, x], [b, y]) => y - x || a.localeCompare(b),
  )
  return entries.length === 0
    ? 'no error codes reported'
    : entries.map(([code, count]) => `${count} × ${code}`).join(', ')
}

const JSON_TYPES = new Set(['json', 'jsonb'])

/**
 * Build the serializer that turns a decrypted JS plaintext into the text
 * parameter the write casts to the plaintext column's type. Returns
 * `undefined` for a value that has no faithful text form for that type (a
 * scalar column decrypting to `null`), which the caller counts as skipped
 * rather than writing a NULL that would read as "not yet decrypted".
 *
 * - JSON targets: `JSON.stringify` of whatever came back, so a document that
 *   is itself a string, number or `null` keeps its JSON meaning.
 * - `Date` (when a client reconstructs one): ISO-8601, which Postgres parses
 *   for `date`, `timestamp` and `timestamptz` alike.
 * - `bigint`: its exact decimal string — never through `Number`.
 * - Other scalars: their canonical string; Postgres does the type conversion,
 *   so `numeric`/`real`/`double precision` and integer widths all apply their
 *   own parsing and range checks.
 */
export function plaintextSerializer(
  plaintextSqlType: string,
): (value: unknown) => string | undefined {
  if (JSON_TYPES.has(plaintextSqlType.trim().toLowerCase())) {
    return (value) => JSON.stringify(value === undefined ? null : value)
  }
  return (value) => {
    if (value === null || value === undefined) return undefined
    if (value instanceof Date) return value.toISOString()
    switch (typeof value) {
      case 'string':
        return value
      case 'number':
      case 'bigint':
      case 'boolean':
        return String(value)
      default:
        return JSON.stringify(value)
    }
  }
}

/** One row's decrypted plaintext, with the ciphertext it was decrypted from. */
interface DecryptedWrite {
  pk: string
  /**
   * Text form of the plaintext, cast to the column's type in SQL. `null`
   * clears the column: a row a forced pass skipped.
   */
  value: string | null
  /** The ciphertext as the page query read it (parsed `jsonb`). */
  ciphertext: unknown
}

interface WriteDecryptedChunkOptions {
  tableName: string
  pkColumn: string
  encryptedColumn: string
  plaintextColumn: string
  plaintextSqlType: string
  writes: DecryptedWrite[]
  force: boolean
}

/**
 * One `UPDATE … FROM (VALUES …)` per chunk, the mirror of the forward
 * `writeEncryptedChunk`. Values travel as text and are cast to the column's
 * declared type in SQL, which is what lets one statement serve every type.
 *
 * Two guards keep a concurrent dual-write from being overwritten by an older
 * decrypted value. The page is read, and decrypted, outside the chunk's
 * transaction, so the application can write the row in between:
 *
 * - The ciphertext must still be the one that was decrypted. A row whose
 *   ciphertext changed since it was read is left alone: the application's
 *   dual-write already put the matching plaintext there. This is the only
 *   guard under `force`, where the plaintext is expected to be set.
 * - Unforced, the plaintext must still be NULL.
 *
 * A row left alone by either guard is still counted as processed. That is
 * safe for coverage: if it was left with a NULL plaintext,
 * `countUndecrypted` still counts it and a later run retries it.
 *
 * Each row binds two parameters — the primary key, and one `jsonb` array
 * `[plaintext, ciphertext]` — which is what {@link MAX_DECRYPT_CHUNK_SIZE}
 * is computed from.
 *
 * Identifiers are interpolated, never bound, because SQL cannot bind them:
 * the table and columns are quoted with `quoteIdent`/`qualifyTable`, and
 * `plaintextSqlType` is `format_type()` output read from the catalog. Every
 * value travels as a bound parameter.
 */
async function writeDecryptedChunk(
  db: ClientBase,
  opts: WriteDecryptedChunkOptions,
): Promise<void> {
  if (opts.writes.length === 0) return

  const table = qualifyTable(opts.tableName)
  const pk = quoteIdent(opts.pkColumn)
  const enc = quoteIdent(opts.encryptedColumn)
  const plain = quoteIdent(opts.plaintextColumn)

  const params: unknown[] = []
  const valuesSql = opts.writes
    .map(({ pk: pkValue, value, ciphertext }) => {
      params.push(pkValue)
      const pkParam = `$${params.length}`
      params.push(JSON.stringify([value, ciphertext]))
      return `(${pkParam}, $${params.length}::jsonb)`
    })
    .join(', ')

  const unchanged = `t.${pk}::text = v.pk::text AND t.${enc}::jsonb = v.w->1`
  const where = opts.force ? unchanged : `${unchanged} AND t.${plain} IS NULL`

  // `plaintextSqlType` is `format_type()` output from the catalog — valid,
  // already-quoted type syntax — never user input.
  try {
    await db.query(
      `
    UPDATE ${table} AS t
    SET ${plain} = (v.w->>0)::${opts.plaintextSqlType}
    FROM (VALUES ${valuesSql}) AS v(pk, w)
    WHERE ${where}
  `,
      params,
    )
  } catch (error) {
    throw new PlaintextWriteError(
      sqlStateOf(error),
      opts.plaintextColumn,
      opts.plaintextSqlType,
      constraintOf(error),
    )
  }
}

/** A driver error's SQLSTATE, when it is one (five uppercase alphanumerics). */
function sqlStateOf(error: unknown): string | undefined {
  const code = fieldOf(error, 'code')
  return code !== undefined && /^[0-9A-Z]{5}$/.test(code) ? code : undefined
}

/** A driver error's constraint name — schema metadata, not row data. */
function constraintOf(error: unknown): string | undefined {
  return fieldOf(error, 'constraint')
}

function fieldOf(error: unknown, key: string): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const value: unknown = Reflect.get(error, key)
  return typeof value === 'string' ? value : undefined
}
