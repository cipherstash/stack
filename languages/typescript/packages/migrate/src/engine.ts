import type { ClientBase, PoolClient } from 'pg'
import {
  ColumnMigration,
  ColumnMigrationError,
  DIRECTION_VOCABULARY,
  type ForcedBy,
  type MigrationDirection,
} from './column-migration.js'
import type { KeysetPage } from './cursor.js'
import { appendEvent } from './state.js'

/**
 * A chunk whose network work (encrypt or decrypt) is done and whose database
 * write is ready to run inside the chunk's transaction.
 */
export interface PreparedChunk {
  /** Issue the chunk's writes on `db`. Runs between `BEGIN` and `COMMIT`. */
  write(db: ClientBase): Promise<void>
  /**
   * Rows in this chunk that were visited but deliberately not written — for
   * the reverse direction, values that could not be decrypted. Default `0`.
   */
  skipped?: number
  /** Extra fields merged into this chunk's checkpoint event `details`. */
  checkpointDetails?: Record<string, unknown>
}

/** Context handed to {@link ChunkedRunOptions.prepareChunk}. */
export interface ChunkContext {
  /** Zero-based index of this chunk within the current run. */
  chunkIndex: number
  /** True when this run resumed from a recorded checkpoint. */
  resumed: boolean
  /** Whether this run is a forced pass (see {@link ChunkedRunResult.force}). */
  force: boolean
}

/** The pass mode handed to the page and count callbacks. */
export interface PassMode {
  /** Overwrite values already in the target instead of skipping them. */
  force: boolean
}

/** Progress snapshot, emitted after every committed chunk. */
export interface ChunkedRunProgress {
  rowsProcessed: number
  rowsTotal: number
  lastPk: string | null
  chunkSize: number
  chunkIndex: number
  /** Cumulative skipped rows, including a resumed pass's. */
  rowsSkipped: number
}

export interface ChunkedRunOptions<Row extends { pk: string }> {
  db: PoolClient
  tableName: string
  /**
   * The SOURCE column, which this run's events are recorded under: the
   * plaintext column forward, the encrypted column reverse.
   */
  stateColumn: string
  /** The TARGET column this run fills: the column migration's twin. */
  twinColumn: string
  direction: MigrationDirection
  chunkSize: number
  signal?: AbortSignal
  /**
   * Ask for a forced pass. An open obligation on the column migration forces
   * the run whatever this says; {@link ChunkedRunResult.forcedBy} says why.
   */
  force?: boolean
  /**
   * Rows still to process, for `rowsTotal`. Evaluated once, at start, after
   * the resume point is known: `after` is the cursor the run restarts from
   * (`null` for a fresh pass). Count only rows past it — rows before it were
   * already visited and are in the resumed `rowsProcessed`, including any the
   * previous run skipped, which still match the pending predicate.
   */
  countPending(after: string | null, mode: PassMode): Promise<number>
  /** The next keyset page after `after` (exclusive). */
  fetchPage(
    after: string | null,
    limit: number,
    mode: PassMode,
  ): Promise<KeysetPage<Row>>
  /**
   * Do the chunk's network work BEFORE the transaction opens, so a slow
   * ZeroKMS round trip never holds row locks. Throwing aborts the run (an
   * `error` event is recorded and the error rethrown) with nothing written
   * for this chunk and the cursor where it was.
   */
  prepareChunk(rows: Row[], context: ChunkContext): Promise<PreparedChunk>
  /**
   * Fields merged into EVERY event's `details` (started, checkpoint,
   * completed, error) — e.g. the reverse run records which plaintext column
   * it fills, so later commands can recover the pairing from state alone.
   */
  baseDetails?: Record<string, unknown>
  /**
   * Fields of a failure that are safe to store in the `error` event: names,
   * codes and counts, never a value. The event never stores the error's
   * message, which a database or client may fill with row data; it stores
   * `err.name` and whatever this returns.
   */
  errorDetails?: (error: unknown) => Record<string, unknown> | undefined
  onProgress?: (progress: ChunkedRunProgress) => void
}

export interface ChunkedRunResult {
  resumed: boolean
  rowsProcessed: number
  rowsTotal: number
  completed: boolean
  rowsSkipped: number
  /** Whether this run was a forced pass. */
  force: boolean
  /**
   * Why it was: the caller asked (`caller`), or the column migration owed a
   * forced pass (`forced-pass`: an earlier forced pass has not completed;
   * `existing-values`: the reverse twin held values before the column
   * migration began). `null` for an unforced run.
   */
  forcedBy: ForcedBy
}

/**
 * The chunked, resumable, keyset-paginated loop both backfill directions run.
 *
 * Per chunk: fetch the next page after the cursor, prepare it (network work,
 * outside any transaction), then in ONE transaction write it and append a
 * checkpoint event, and commit. The checkpoint and the data land atomically,
 * so a crash can never record progress for rows that were not written, and
 * the `target IS NULL` guard in every page query makes a lost cursor
 * harmless: a re-run simply re-selects whatever is still pending.
 *
 * Mode and resume come from the column migration ({@link ColumnMigration}):
 * an open obligation forces the run, and the run resumes from this
 * direction's latest checkpoint, or from an `error` event carrying the last
 * committed cursor, when that pass ran in the same mode. Anything else starts
 * a fresh pass from the beginning, which the idempotency guard keeps cheap.
 * Every event records the mode (`details.force`), which is what lets a later
 * run tell a forced pass from an unforced one.
 *
 * Refused, before anything is recorded, while the other direction's column
 * migration on the same pair is open, or when `twinColumn` contradicts the
 * twin the column migration in progress recorded.
 *
 * Abort: `signal` is checked between chunks; the in-flight chunk always
 * finishes and checkpoints first.
 */
export async function runChunkedMigration<Row extends { pk: string }>(
  options: ChunkedRunOptions<Row>,
): Promise<ChunkedRunResult> {
  const { db, tableName, stateColumn, chunkSize, direction } = options
  const events = DIRECTION_VOCABULARY[direction]

  const migration = await ColumnMigration.load(db, {
    table: tableName,
    column: stateColumn,
    direction,
    twin: options.twinColumn,
    manifest: null,
  })
  const counterpart = migration.counterpartMessage()
  if (counterpart !== null) {
    throw new ColumnMigrationError('counterpart-open', counterpart)
  }
  const plan = await migration.planPass({ force: options.force ?? false })
  const { force, forcedBy } = plan
  const mode: PassMode = { force }
  // The pairing and mode are recorded on every event whatever the caller
  // passes, so a later run with a different twin is refused rather than
  // resumed. Caller details are spread before them on every event.
  const base = {
    ...options.baseDetails,
    [events.twinKey]: options.twinColumn,
    force,
  }

  const resumedFrom = plan.resumeFrom
  const resumeCursor = resumedFrom ? resumedFrom.cursorValue : null
  const resumed = resumeCursor !== null
  const priorProcessed = resumedFrom ? (resumedFrom.rowsProcessed ?? 0) : 0
  const priorSkipped = resumedFrom ? readSkipped(resumedFrom.details) : 0

  const pending = await options.countPending(resumeCursor, mode)
  const rowsTotal = priorProcessed + pending

  await appendEvent(db, {
    tableName,
    columnName: stateColumn,
    event: events.started,
    phase: events.runningPhase,
    cursorValue: resumeCursor,
    rowsProcessed: priorProcessed,
    rowsTotal,
    details: {
      ...base,
      ...(forcedBy !== null ? { forcedBy } : {}),
      chunkSize,
      resumed,
    },
  })

  let cursor = resumeCursor
  let rowsProcessed = priorProcessed
  let rowsSkipped = priorSkipped
  let chunkIndex = 0
  let completed = false

  try {
    while (true) {
      if (options.signal?.aborted) break

      const page = await options.fetchPage(cursor, chunkSize, mode)
      if (page.rows.length === 0) {
        completed = true
        break
      }

      const prepared = await options.prepareChunk(page.rows, {
        chunkIndex,
        resumed,
        force,
      })
      const chunkSkipped = prepared.skipped ?? 0

      // The counters and cursor advance only once the chunk has COMMITTED:
      // an `error` event records them, and a resumed run trusts them.
      const nextProcessed = rowsProcessed + page.rows.length
      const nextSkipped = rowsSkipped + chunkSkipped
      await db.query('BEGIN')
      try {
        await prepared.write(db)
        await appendEvent(db, {
          tableName,
          columnName: stateColumn,
          event: events.checkpoint,
          phase: events.runningPhase,
          cursorValue: page.lastPk,
          rowsProcessed: nextProcessed,
          rowsTotal,
          // The caller's fields go first: a resume reads the engine's.
          details: {
            ...prepared.checkpointDetails,
            ...base,
            chunkIndex,
            chunkRows: page.rows.length,
            chunkSkipped,
            rowsSkipped: nextSkipped,
          },
        })
        await db.query('COMMIT')
      } catch (err) {
        await db.query('ROLLBACK').catch(() => {})
        throw err
      }
      rowsProcessed = nextProcessed
      rowsSkipped = nextSkipped
      cursor = page.lastPk

      options.onProgress?.({
        rowsProcessed,
        rowsTotal,
        lastPk: cursor,
        chunkSize,
        chunkIndex,
        rowsSkipped,
      })
      chunkIndex += 1
    }

    if (completed) {
      await appendEvent(db, {
        tableName,
        columnName: stateColumn,
        event: events.completed,
        phase: events.completedPhase,
        cursorValue: cursor,
        rowsProcessed,
        rowsTotal,
        details: { ...base, chunkCount: chunkIndex, rowsSkipped },
      })
    }
  } catch (err) {
    await appendEvent(db, {
      tableName,
      columnName: stateColumn,
      event: 'error',
      phase: events.runningPhase,
      cursorValue: cursor,
      rowsProcessed,
      rowsTotal,
      details: {
        ...options.errorDetails?.(err),
        ...base,
        errorName: safeErrorName(err),
        chunkIndex,
        rowsSkipped,
      },
    })
    throw err
  }

  return {
    resumed,
    rowsProcessed,
    rowsTotal,
    completed,
    rowsSkipped,
    force,
    forcedBy,
  }
}

/**
 * The error's `name` when it looks like a class name, else `Error`. Never its
 * message: a database or client error can carry row data there.
 */
function safeErrorName(error: unknown): string {
  const name = error instanceof Error ? error.name : undefined
  return name !== undefined && /^[A-Za-z_$][\w$.]{0,63}$/.test(name)
    ? name
    : 'Error'
}

/** Cumulative skipped count from a checkpoint's details; `0` when absent. */
function readSkipped(details: Record<string, unknown> | null): number {
  const value = details?.rowsSkipped
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}
