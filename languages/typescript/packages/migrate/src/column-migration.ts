import type { ClientBase } from 'pg'
import { columnHasValues } from './cursor.js'
import { type Manifest, readManifest } from './manifest.js'
import {
  appendEvent,
  isReverseMigrationPhase,
  type MigrationEvent,
  type MigrationPhase,
  type MigrationStateRow,
  rowToState,
} from './state.js'
import { columnExists } from './version.js'

/**
 * Which way a column migration moves data: `forward` (plaintext to
 * encrypted) or `reverse` (encrypted to plaintext). See `CONTEXT.md`.
 */
export type MigrationDirection = 'forward' | 'reverse'

/**
 * The `cs_migrations` vocabulary one direction writes. Both directions run
 * the same rules over different event names, so their histories stay apart
 * and neither resumes from the other's cursor.
 */
export interface DirectionVocabulary {
  /** Starts the column migration: dual-writes are confirmed deployed. */
  readonly dualWriting: MigrationEvent
  readonly dualWritingPhase: MigrationPhase
  readonly started: MigrationEvent
  /** The event a resume looks for. Its `cursorValue` is the restart point. */
  readonly checkpoint: MigrationEvent
  readonly completed: MigrationEvent
  /** Phase recorded on `started`, every `checkpoint`, and any `error`. */
  readonly runningPhase: MigrationPhase
  readonly completedPhase: MigrationPhase
  /** Recorded when the drop of the source column is generated. */
  readonly dropped: MigrationEvent
  readonly droppedPhase: MigrationPhase
  /** The `details` key every event uses to name the twin, when it does. */
  readonly twinKey: string
}

export const DIRECTION_VOCABULARY: Readonly<
  Record<MigrationDirection, DirectionVocabulary>
> = {
  forward: {
    dualWriting: 'dual_writing',
    dualWritingPhase: 'dual-writing',
    started: 'backfill_started',
    checkpoint: 'backfill_checkpoint',
    completed: 'backfilled',
    runningPhase: 'backfilling',
    completedPhase: 'backfilled',
    dropped: 'dropped',
    droppedPhase: 'dropped',
    twinKey: 'encryptedColumn',
  },
  reverse: {
    dualWriting: 'decrypt_dual_writing',
    dualWritingPhase: 'decrypt-dual-writing',
    started: 'decrypt_started',
    checkpoint: 'decrypt_checkpoint',
    completed: 'decrypted',
    runningPhase: 'decrypting',
    completedPhase: 'decrypted',
    dropped: 'encrypted_dropped',
    droppedPhase: 'encrypted-dropped',
    twinKey: 'plaintextColumn',
  },
}

const OPPOSITE: Record<MigrationDirection, MigrationDirection> = {
  forward: 'reverse',
  reverse: 'forward',
}

/**
 * An open obligation to complete a forced pass. While one is open, every run
 * is a forced pass, whatever the caller passes. See this package's ADR 0001,
 * "A forced pass is an obligation"
 * (`docs/adr/0001-forced-pass-is-an-obligation.md`).
 *
 * - `existing-values`: a reverse column migration began on a twin that
 *   already held values. A {@link Waiver} can close it until a forced pass
 *   starts.
 * - `forced-pass`: a forced pass started. Only a completed forced pass closes
 *   it.
 */
export type Obligation = {
  kind: 'forced-pass'
  /** Id of the event that opened it, or `null` when no event records it yet. */
  openedAt: string | null
} & (
  | {
      reason: 'existing-values'
      /** Whether a waiver may still close it: always, for this reason. */
      waivable: true
    }
  | {
      reason: 'forced-pass'
      /** Whether a waiver may still close it: never, for this reason. */
      waivable: false
    }
)

/**
 * The operator's recorded assertion that a twin's existing values are already
 * current: the application has written that column on every insert and
 * update. Reverse only.
 */
export type Waiver = 'plaintext-current'

/** Why a run is a forced pass, or `null` for an unforced one. */
export type ForcedBy = 'caller' | Obligation['reason'] | null

/** The other direction's column migration on the same pair, while open. */
export interface OpenCounterpart {
  direction: MigrationDirection
  /** The column its events are keyed by: this column migration's twin. */
  column: string
  phase: MigrationPhase
}

/** What the event history says about one column migration. */
export interface ColumnMigrationState {
  direction: MigrationDirection
  /**
   * Latest event of this direction under this column, whether or not it
   * belongs to the column migration in progress.
   */
  latest: MigrationStateRow | null
  /**
   * Phase of the column migration the column is in now, or `null` when there
   * is none (no history, or only a finished column migration's).
   */
  phase: MigrationPhase | null
  /** `phase` is set and the drop has not been generated. */
  open: boolean
  /** The drop of the source column has been generated (`phase` is the last). */
  dropGenerated: boolean
  /** The twin the current column migration's events name, if they do. */
  recordedTwin: string | undefined
  /** At most one: there is only one kind of obligation. */
  obligations: readonly Obligation[]
}

/**
 * The column migration rules, as a pure function of the event history.
 *
 * `history` is the column's events in `id` order (any subset that contains
 * every non-checkpoint event and the latest checkpoint). Events of the other
 * direction are ignored. `recordedTwinHistory` is the events under the twin
 * the latest event names: a column migration of the twin in the other
 * direction, recorded after a drop, means the drop was applied and the pair
 * was migrated back (for reverse, the column encrypted again; forward, the
 * column decrypted again), so this history is finished.
 *
 * Obligations are scoped to the column migration in progress: the events
 * since its latest dual-write confirmation (all of them when a pass ran
 * without one).
 */
export function deriveColumnMigration(input: {
  direction: MigrationDirection
  history: readonly MigrationStateRow[]
  recordedTwinHistory?: readonly MigrationStateRow[]
}): ColumnMigrationState {
  const { direction } = input
  const vocab = DIRECTION_VOCABULARY[direction]
  const events = ofDirection(direction, input.history)
  const latest = events.at(-1) ?? null

  const none: ColumnMigrationState = {
    direction,
    latest,
    phase: null,
    open: false,
    dropGenerated: false,
    recordedTwin: undefined,
    obligations: [],
  }
  if (latest === null) return none

  const recordedTwin = twinNamedBy(vocab, latest)
  if (latest.phase === vocab.droppedPhase) {
    const superseded = ofDirection(
      OPPOSITE[direction],
      input.recordedTwinHistory ?? [],
    ).some((row) => BigInt(row.id) > BigInt(latest.id))
    if (superseded) return none
  }

  let scopeStart = 0
  for (const [i, e] of events.entries()) {
    if (e.event === vocab.dualWriting) scopeStart = i
  }
  const scope = events.slice(scopeStart)

  let obligation: Obligation | null = null
  // The mode of the latest pass started, for completion events written
  // before every event recorded its own (see `passForced`).
  let startedForced = false
  for (const e of scope) {
    if (e.event === vocab.started) startedForced = isForced(e)
    if (e.event === vocab.dualWriting) {
      obligation = owesUpFront(e)
        ? {
            kind: 'forced-pass',
            reason: 'existing-values',
            openedAt: e.id,
            waivable: true,
          }
        : null
    } else if (e.event === vocab.completed) {
      if (passForced(e, startedForced)) obligation = null
    } else if (e.phase === vocab.runningPhase && isForced(e)) {
      if (obligation?.reason !== 'forced-pass') {
        obligation = {
          kind: 'forced-pass',
          reason: 'forced-pass',
          openedAt: e.id,
          waivable: false,
        }
      }
    }
  }

  return {
    direction,
    latest,
    phase: latest.phase,
    open: latest.phase !== vocab.droppedPhase,
    dropGenerated: latest.phase === vocab.droppedPhase,
    recordedTwin,
    obligations: obligation === null ? [] : [obligation],
  }
}

/**
 * The other direction's column migration on this pair, when it is open: at
 * most one column migration is open per column pair. `twinHistory` is the
 * events keyed by the twin, which is where the other direction records them.
 */
export function openCounterpart(input: {
  direction: MigrationDirection
  twin: string
  twinHistory: readonly MigrationStateRow[]
}): OpenCounterpart | null {
  const direction = OPPOSITE[input.direction]
  const latest = ofDirection(direction, input.twinHistory).at(-1)
  if (latest === undefined) return null
  if (latest.phase === DIRECTION_VOCABULARY[direction].droppedPhase) return null
  return { direction, column: input.twin, phase: latest.phase }
}

/** Where the latest backfill pass stands, from its latest event. */
export interface PassProgress {
  rowsProcessed: number
  /** `null` before a pass has counted its rows. */
  rowsTotal: number | null
  /** Cumulative rows the pass visited but could not write. */
  rowsSkipped: number | null
  /** The latest run failed (an `error` event); a re-run resumes it. */
  failed: boolean
  /** The pass completed. */
  completed: boolean
}

/**
 * The latest pass's progress, or `null` when no pass has run in the column
 * migration in progress.
 */
export function passProgress(state: ColumnMigrationState): PassProgress | null {
  const { latest } = state
  if (state.phase === null || latest === null) return null
  const vocab = DIRECTION_VOCABULARY[state.direction]
  if (latest.phase !== vocab.runningPhase && latest.event !== vocab.completed) {
    return null
  }
  const skipped = latest.details?.rowsSkipped
  return {
    rowsProcessed: latest.rowsProcessed ?? 0,
    rowsTotal: latest.rowsTotal,
    rowsSkipped:
      typeof skipped === 'number' && Number.isFinite(skipped) ? skipped : null,
    failed: latest.event === 'error',
    completed: latest.event === vocab.completed,
  }
}

/** How the next run will go: its mode, why, and where it resumes. */
export type PassPlan = {
  /**
   * The event the run resumes from (a checkpoint, or an error carrying the
   * last committed cursor), or `null` for a fresh pass from the first row.
   */
  resumeFrom: MigrationStateRow | null
} & (
  | { force: false; forcedBy: null }
  | { force: true; forcedBy: NonNullable<ForcedBy> }
)

/**
 * Plan the next run of a column migration. An open obligation forces it. A
 * run resumes only a pass of the same mode: a forced run never resumes an
 * unforced pass, whose rows before the cursor were never overwritten.
 *
 * `twinHasValues` covers a reverse pass started with no column migration on
 * record (an embedded worker that never confirmed dual-writes): the twin
 * already holding values opens the up-front obligation there and then.
 */
export function planPassFor(
  state: ColumnMigrationState,
  opts: { force: boolean; twinHasValues?: boolean },
): PassPlan {
  const vocab = DIRECTION_VOCABULARY[state.direction]
  let forcedBy: ForcedBy = opts.force ? 'caller' : null
  if (forcedBy === null) {
    const owed = state.obligations[0]
    if (owed !== undefined) forcedBy = owed.reason
    else if (
      state.direction === 'reverse' &&
      state.phase === null &&
      opts.twinHasValues === true
    ) {
      forcedBy = 'existing-values'
    }
  }
  const force = forcedBy !== null

  const last = state.phase === null ? null : state.latest
  const resumable =
    last !== null &&
    (last.event === vocab.checkpoint ||
      (last.event === 'error' &&
        last.phase === vocab.runningPhase &&
        last.cursorValue !== null)) &&
    isForced(last) === force
  const resumeFrom = resumable ? last : null
  return forcedBy === null
    ? { force: false, forcedBy, resumeFrom }
    : { force: true, forcedBy, resumeFrom }
}

/**
 * Thrown when a column migration refuses a step. The message carries table,
 * column and phase names only — never a value — so callers may print it.
 */
export class ColumnMigrationError extends Error {
  constructor(
    readonly code:
      | 'counterpart-open'
      | 'twin-mismatch'
      | 'waiver-refused'
      | 'wrong-phase'
      | 'obligation-open',
    message: string,
  ) {
    super(message)
    this.name = 'ColumnMigrationError'
  }
}

/** How a column migration's twin was decided. */
export type TwinSource =
  | 'flag'
  | 'recorded'
  | 'manifest'
  | 'convention'
  | 'fallback'

export interface LoadColumnMigrationOptions {
  /** Physical table; `schema.table` supported. */
  table: string
  /** The SOURCE column: the one this direction migrates away from. */
  column: string
  direction: MigrationDirection
  /**
   * The twin the caller names. Refused when it contradicts the twin the
   * column migration in progress recorded.
   */
  twin?: string
  /**
   * The forward manifest, for the twin's name when none is given or
   * recorded. `undefined` reads `.cipherstash/migrations.json` from the
   * current directory; `null` skips it.
   */
  manifest?: Manifest | null
}

/**
 * One direction applied to one column, read from `cipherstash.cs_migrations`.
 * The single owner of the column-migration rules: which twin it fills
 * (recorded, then manifest, then derived), whether it is the one in
 * progress, which obligations are open, and which phase changes are allowed.
 * Commands and the backfill engine ask it instead of reading event names.
 *
 * A loaded value is a snapshot. Each method that records an event returns a
 * freshly loaded one.
 */
export class ColumnMigration implements ColumnMigrationState {
  readonly direction: MigrationDirection
  readonly latest: MigrationStateRow | null
  readonly phase: MigrationPhase | null
  readonly open: boolean
  readonly dropGenerated: boolean
  readonly recordedTwin: string | undefined
  readonly obligations: readonly Obligation[]

  private constructor(
    private readonly db: ClientBase,
    readonly table: string,
    readonly column: string,
    state: ColumnMigrationState,
    /** The twin this column migration fills (reverse) or writes (forward). */
    readonly twin: { column: string; via: TwinSource },
    /** The other direction's column migration on this pair, when open. */
    readonly blockedBy: OpenCounterpart | null,
    private readonly manifest: Manifest | null | undefined,
  ) {
    this.direction = state.direction
    this.latest = state.latest
    this.phase = state.phase
    this.open = state.open
    this.dropGenerated = state.dropGenerated
    this.recordedTwin = state.recordedTwin
    this.obligations = state.obligations
  }

  static async load(
    db: ClientBase,
    opts: LoadColumnMigrationOptions,
  ): Promise<ColumnMigration> {
    const { table, column, direction } = opts
    const history = await readHistory(db, table, column)
    const named = latestTwin(direction, history)
    const namedHistory =
      named === undefined ? [] : await readHistory(db, table, named)
    const state = deriveColumnMigration({
      direction,
      history,
      recordedTwinHistory: namedHistory,
    })

    const recorded = state.recordedTwin
    let twin: { column: string; via: TwinSource }
    if (opts.twin !== undefined) {
      if (recorded !== undefined && recorded !== opts.twin) {
        throw new ColumnMigrationError(
          'twin-mismatch',
          `${table}.${column} is already being migrated with "${recorded}" (recorded in cipherstash.cs_migrations), not "${opts.twin}". Refusing to switch columns in the middle of a column migration: the coverage check before ${column} is dropped would then verify the wrong column. Continue with "${recorded}".`,
        )
      }
      twin = { column: opts.twin, via: 'flag' }
    } else if (recorded !== undefined) {
      twin = { column: recorded, via: 'recorded' }
    } else {
      const manifest =
        opts.manifest === undefined ? await readManifest() : opts.manifest
      const fromManifest = manifestTwin(direction, manifest, table, column)
      twin =
        fromManifest !== undefined
          ? { column: fromManifest, via: 'manifest' }
          : deriveTwinName(direction, column)
    }
    if (twin.column === column) {
      throw new ColumnMigrationError(
        'twin-mismatch',
        `The twin of ${table}.${column} cannot be ${column} itself.`,
      )
    }

    const twinHistory =
      twin.column === named
        ? namedHistory
        : await readHistory(db, table, twin.column)
    const blockedBy = openCounterpart({
      direction,
      twin: twin.column,
      twinHistory,
    })
    return new ColumnMigration(
      db,
      table,
      column,
      state,
      twin,
      blockedBy,
      opts.manifest,
    )
  }

  /**
   * Whether the twin already holds values a reverse column migration did not
   * write: there is no column migration in progress, and the twin exists
   * with at least one non-NULL value. Opens the up-front obligation. Always
   * `false` forward.
   */
  async existingTwinValues(): Promise<boolean> {
    if (this.direction !== 'reverse' || this.phase !== null) return false
    if (!(await columnExists(this.db, this.table, this.twin.column))) {
      return false
    }
    return columnHasValues(this.db, this.table, this.twin.column)
  }

  /** How the next run will go; read-only. See {@link planPassFor}. */
  async planPass(opts: { force: boolean }): Promise<PassPlan> {
    const twinHasValues =
      !opts.force && this.obligations.length === 0
        ? await this.existingTwinValues()
        : false
    return planPassFor(this, { force: opts.force, twinHasValues })
  }

  /**
   * The message for {@link blockedBy}, or `null`. Names and phases only.
   */
  counterpartMessage(): string | null {
    const other = this.blockedBy
    if (other === null) return null
    const verb = other.direction === 'forward' ? 'encryption' : 'decryption'
    const mine = this.direction === 'forward' ? 'encryption' : 'decryption'
    return `${this.table}.${this.twin.column} has a ${other.direction} ${verb} with ${this.column} that is still open at '${other.phase}' in cipherstash.cs_migrations. At most one column migration may be open per pair of columns, so a ${this.direction} ${mine} cannot start until it is dropped or abandoned.`
  }

  /**
   * Start the column migration: the application writes both columns on
   * every insert and update. Records the dual-write confirmation, naming the
   * twin. Over a reverse twin that already holds values, this opens the
   * up-front obligation unless `waiver` is given.
   *
   * On a column migration already in progress this records nothing, except
   * that a `waiver` closes an up-front obligation no forced pass has started
   * on. A waiver given once a forced pass has started is refused.
   */
  async confirmDualWrites(
    opts: { waiver?: Waiver } = {},
  ): Promise<ColumnMigration> {
    const vocab = DIRECTION_VOCABULARY[this.direction]
    const counterpart = this.counterpartMessage()
    if (counterpart !== null) {
      throw new ColumnMigrationError('counterpart-open', counterpart)
    }
    if (opts.waiver !== undefined && this.direction !== 'reverse') {
      throw new ColumnMigrationError(
        'waiver-refused',
        `A waiver applies to a reverse column migration only; ${this.table}.${this.column} is ${this.direction}.`,
      )
    }

    let existingTwinValues: boolean
    if (this.phase !== null) {
      const owed = this.obligations[0]
      if (opts.waiver === undefined || owed === undefined) return this
      if (!owed.waivable) {
        throw new ColumnMigrationError(
          'waiver-refused',
          `A forced pass over ${this.table}.${this.twin.column} has already started, so it may hold a mix of old and overwritten values. A waiver cannot close that obligation: re-run the backfill to complete the forced pass.`,
        )
      }
      existingTwinValues = true
    } else {
      existingTwinValues = await this.existingTwinValues()
    }

    await appendEvent(this.db, {
      tableName: this.table,
      columnName: this.column,
      event: vocab.dualWriting,
      phase: vocab.dualWritingPhase,
      details: {
        [vocab.twinKey]: this.twin.column,
        ...(existingTwinValues ? { existingTwinValues: true } : {}),
        ...(existingTwinValues && opts.waiver !== undefined
          ? { waiver: opts.waiver }
          : {}),
      },
    })
    return this.reload()
  }

  /**
   * Record that the drop of the source column was generated. Allowed only
   * once the backfill completed with no obligation open.
   */
  async recordDropGenerated(
    details: Record<string, unknown> = {},
  ): Promise<ColumnMigration> {
    const vocab = DIRECTION_VOCABULARY[this.direction]
    if (this.phase !== vocab.completedPhase) {
      throw new ColumnMigrationError(
        'wrong-phase',
        `${this.table}.${this.column} is in phase '${this.phase ?? '—'}', so its drop cannot be generated. It must be '${vocab.completedPhase}'.`,
      )
    }
    const owed = this.obligations[0]
    if (owed !== undefined) {
      throw new ColumnMigrationError(
        'obligation-open',
        `${this.table}.${this.column} still owes a forced pass (${owed.reason}), so its drop cannot be generated. Re-run the backfill to complete it.`,
      )
    }
    await appendEvent(this.db, {
      tableName: this.table,
      columnName: this.column,
      event: vocab.dropped,
      phase: vocab.droppedPhase,
      details: { [vocab.twinKey]: this.twin.column, ...details },
    })
    return this.reload()
  }

  /**
   * Record that the source column is gone though no drop was generated: it
   * was removed outside stash. Closes the column migration so the other
   * direction may start on the pair. Allowed only while it is open.
   */
  async recordSourceRemoved(
    details: Record<string, unknown> = {},
  ): Promise<ColumnMigration> {
    const vocab = DIRECTION_VOCABULARY[this.direction]
    if (!this.open) {
      throw new ColumnMigrationError(
        'wrong-phase',
        `${this.table}.${this.column} has no open column migration to close.`,
      )
    }
    await appendEvent(this.db, {
      tableName: this.table,
      columnName: this.column,
      event: vocab.dropped,
      phase: vocab.droppedPhase,
      details: {
        [vocab.twinKey]: this.twin.column,
        observedAbsent: true,
        ...details,
      },
    })
    return this.reload()
  }

  private reload(): Promise<ColumnMigration> {
    return ColumnMigration.load(this.db, {
      table: this.table,
      column: this.column,
      direction: this.direction,
      twin: this.twin.via === 'flag' ? this.twin.column : undefined,
      manifest: this.manifest,
    })
  }
}

/**
 * The twin's name when nothing better is known. Reverse: the
 * `<name>_encrypted` convention stripped, else `<column>_plaintext`, so a
 * derived name never collides with the column itself. Forward:
 * `<column>_encrypted`.
 */
export function deriveTwinName(
  direction: MigrationDirection,
  column: string,
): { column: string; via: 'convention' | 'fallback' } {
  if (direction === 'forward') {
    return { column: `${column}_encrypted`, via: 'convention' }
  }
  const suffix = '_encrypted'
  return column.endsWith(suffix) && column.length > suffix.length
    ? { column: column.slice(0, -suffix.length), via: 'convention' }
    : { column: `${column}_plaintext`, via: 'fallback' }
}

/**
 * The forward manifest's twin for this column. Reverse: the entry whose
 * recorded `encryptedColumn` is it (or, for entries written before that field
 * existed, whose `<column>_encrypted` convention names it), giving the
 * original plaintext name. Forward: the entry's `encryptedColumn`.
 */
export function manifestTwin(
  direction: MigrationDirection,
  manifest: Manifest | null,
  table: string,
  column: string,
): string | undefined {
  const entries = manifest?.tables[table] ?? []
  if (direction === 'forward') {
    return entries.find((e) => e.column === column)?.encryptedColumn
  }
  const entry =
    entries.find((e) => e.encryptedColumn === column) ??
    entries.find(
      (e) =>
        e.encryptedColumn === undefined && `${e.column}_encrypted` === column,
    )
  return entry?.column
}

function ofDirection(
  direction: MigrationDirection,
  rows: readonly MigrationStateRow[],
): MigrationStateRow[] {
  const reverse = direction === 'reverse'
  return rows
    .filter((row) => isReverseMigrationPhase(row.phase) === reverse)
    .sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1))
}

function isForced(row: MigrationStateRow): boolean {
  return row.details?.force === true
}

/**
 * Whether a completion event closes a forced pass. An earlier release
 * recorded `force` on the started event only, so a completion without the
 * key takes the mode of the pass started before it.
 */
function passForced(row: MigrationStateRow, startedForced: boolean): boolean {
  // `details` is jsonb: a hand-written scalar must not throw on `in`.
  if (typeof row.details === 'object' && row.details !== null) {
    if ('force' in row.details) return isForced(row)
  }
  return startedForced
}

/**
 * Whether a dual-write confirmation opens the up-front obligation: the twin
 * already held values and no waiver was given. An earlier release recorded
 * the same choice as `acknowledgedWith: 'force'`.
 */
function owesUpFront(row: MigrationStateRow): boolean {
  if (row.details?.acknowledgedWith === 'force') return true
  return (
    row.details?.existingTwinValues === true &&
    row.details?.waiver === undefined
  )
}

function twinNamedBy(
  vocab: DirectionVocabulary,
  row: MigrationStateRow,
): string | undefined {
  const value = row.details?.[vocab.twinKey]
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function latestTwin(
  direction: MigrationDirection,
  history: readonly MigrationStateRow[],
): string | undefined {
  const latest = ofDirection(direction, history).at(-1)
  return latest && twinNamedBy(DIRECTION_VOCABULARY[direction], latest)
}

/**
 * The events the rules read for one column: every event except checkpoints,
 * plus the latest checkpoint of each direction (the only one a resume can
 * use). A pass writes one checkpoint per chunk, so this keeps the read small
 * on a large table. A missing `cs_migrations` table reads as no history.
 */
async function readHistory(
  db: ClientBase,
  table: string,
  column: string,
): Promise<MigrationStateRow[]> {
  const checkpoints = [
    DIRECTION_VOCABULARY.forward.checkpoint,
    DIRECTION_VOCABULARY.reverse.checkpoint,
  ]
  try {
    const { rows } = await db.query(
      `SELECT id, table_name, column_name, event, phase, cursor_value, rows_processed, rows_total, details, created_at
       FROM cipherstash.cs_migrations
       WHERE table_name = $1 AND column_name = $2
         AND (event <> ALL($3::text[])
              OR id IN (SELECT max(id) FROM cipherstash.cs_migrations
                        WHERE table_name = $1 AND column_name = $2
                          AND event = ANY($3::text[])
                        GROUP BY event))
       ORDER BY id`,
      [table, column, checkpoints],
    )
    return rows.map(rowToState)
  } catch (error) {
    // 42P01 undefined_table, 3F000 invalid_schema_name: not installed yet.
    const code = (error as { code?: unknown } | null)?.code
    if (code === '42P01' || code === '3F000') return []
    throw error
  }
}
