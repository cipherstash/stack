import type { ClientBase } from 'pg'

/**
 * Discrete event types written to the `cipherstash.cs_migrations` event log.
 *
 * Events are snake_case (for SQL readability); phases are kebab-case (for
 * user-facing CLI output). Most events correspond 1:1 with a phase, except:
 * - `backfill_started` and `backfill_checkpoint` both live inside phase
 *   `backfilling`; the `_started` event records the initial intent (and
 *   whether we resumed), while each `_checkpoint` records a committed chunk.
 * - `error` records a failure at whatever phase was current; it does not
 *   change the effective phase (so a retry resumes from where it failed).
 */
export type MigrationEvent =
  | 'schema_added'
  | 'dual_writing'
  | 'backfill_started'
  | 'backfill_checkpoint'
  | 'backfilled'
  | 'cut_over'
  | 'dropped'
  | 'error'

/**
 * The per-column lifecycle phase as surfaced in status/plan output and
 * accepted by `stash encrypt advance --to <phase>`.
 *
 * ```
 * schema-added  → the <col>_encrypted column exists and is registered with EQL
 * dual-writing  → app writes both plaintext and encrypted on inserts/updates
 * backfilling   → runBackfill is (or has been) encrypting historical rows
 * backfilled    → all historical rows encrypted; safe to cut over reads
 * cut-over      → columns renamed (via eql_v2.rename_encrypted_columns)
 * dropped       → old plaintext column removed
 * ```
 */
export type MigrationPhase =
  | 'schema-added'
  | 'dual-writing'
  | 'backfilling'
  | 'backfilled'
  | 'cut-over'
  | 'dropped'

/**
 * Composite key of `<table>.<column>`. Used as the map key by
 * {@link latestByColumn}.
 */
export type ColumnKey = `${string}.${string}`

/**
 * A single row from `cipherstash.cs_migrations`, decoded with numeric bigints
 * converted to `number` and column names camel-cased. `id` is a string to
 * avoid JavaScript bigint precision loss for very large tables.
 */
export interface MigrationStateRow {
  /** Row id, stringified from the bigint column. Monotonically increasing. */
  id: string
  tableName: string
  columnName: string
  event: MigrationEvent
  /** Effective phase *after* this event. */
  phase: MigrationPhase
  /**
   * Value of `pkColumn` for the last row processed in the most recent
   * chunk. Set on `backfill_checkpoint` and `backfilled`; `null` on other
   * event types. Stored as text so it works for any PK type.
   */
  cursorValue: string | null
  /** Cumulative rows encrypted. `null` on non-backfill events. */
  rowsProcessed: number | null
  /** Target rows for this migration. `null` on non-backfill events. */
  rowsTotal: number | null
  /**
   * Free-form event-specific metadata. Examples: `{ chunkSize, resumed }`
   * on `backfill_started`; `{ message, chunkIndex }` on `error`.
   */
  details: Record<string, unknown> | null
  createdAt: Date
}

/**
 * Input to {@link appendEvent}. All fields other than `tableName`,
 * `columnName`, `event`, and `phase` are optional and stored as `NULL` when
 * omitted.
 */
export interface AppendEventInput {
  tableName: string
  columnName: string
  event: MigrationEvent
  phase: MigrationPhase
  cursorValue?: string | null
  rowsProcessed?: number | null
  rowsTotal?: number | null
  details?: Record<string, unknown> | null
}

/**
 * Append a new event row to `cipherstash.cs_migrations`. The table is
 * append-only — existing rows are never updated, so history is preserved
 * and concurrent writers never clobber each other.
 *
 * The "current state" of a column is derived by selecting the row with the
 * greatest `id` for that `(tableName, columnName)` pair.
 */
export async function appendEvent(
  client: ClientBase,
  input: AppendEventInput,
): Promise<MigrationStateRow> {
  const result = await client.query(
    `INSERT INTO cipherstash.cs_migrations
      (table_name, column_name, event, phase, cursor_value, rows_processed, rows_total, details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, table_name, column_name, event, phase, cursor_value, rows_processed, rows_total, details, created_at`,
    [
      input.tableName,
      input.columnName,
      input.event,
      input.phase,
      input.cursorValue ?? null,
      input.rowsProcessed ?? null,
      input.rowsTotal ?? null,
      input.details ?? null,
    ],
  )
  return rowToState(result.rows[0])
}

/**
 * Return the most recent event row for every column tracked in
 * `cs_migrations`, keyed by `"<tableName>.<columnName>"`. Used by
 * `stash encrypt status` and `plan` to render a table view.
 *
 * Columns with no recorded events are simply absent from the map — there
 * is no synthetic "nothing happened yet" entry.
 */
export async function latestByColumn(
  client: ClientBase,
): Promise<Map<ColumnKey, MigrationStateRow>> {
  const result = await client.query(
    `SELECT DISTINCT ON (table_name, column_name)
       id, table_name, column_name, event, phase, cursor_value, rows_processed, rows_total, details, created_at
     FROM cipherstash.cs_migrations
     ORDER BY table_name, column_name, id DESC`,
  )
  const map = new Map<ColumnKey, MigrationStateRow>()
  for (const row of result.rows) {
    const state = rowToState(row)
    map.set(`${state.tableName}.${state.columnName}`, state)
  }
  return map
}

/**
 * Latest event row for a single column, or `null` if the column has no
 * recorded events. Used by the backfill runner to determine whether it is
 * resuming a checkpoint or starting fresh.
 */
export async function progress(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<MigrationStateRow | null> {
  const result = await client.query(
    `SELECT id, table_name, column_name, event, phase, cursor_value, rows_processed, rows_total, details, created_at
     FROM cipherstash.cs_migrations
     WHERE table_name = $1 AND column_name = $2
     ORDER BY id DESC
     LIMIT 1`,
    [tableName, columnName],
  )
  if (result.rows.length === 0) return null
  return rowToState(result.rows[0])
}

function rowToState(row: {
  id: string | number
  table_name: string
  column_name: string
  event: MigrationEvent
  phase: MigrationPhase
  cursor_value: string | null
  rows_processed: string | number | null
  rows_total: string | number | null
  details: Record<string, unknown> | null
  created_at: Date
}): MigrationStateRow {
  return {
    id: String(row.id),
    tableName: row.table_name,
    columnName: row.column_name,
    event: row.event,
    phase: row.phase,
    cursorValue: row.cursor_value,
    rowsProcessed:
      row.rows_processed === null ? null : Number(row.rows_processed),
    rowsTotal: row.rows_total === null ? null : Number(row.rows_total),
    details: row.details,
    createdAt: row.created_at,
  }
}
