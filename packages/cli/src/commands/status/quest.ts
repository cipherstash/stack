import type { MigrationPhase } from '@cipherstash/migrate'

/** Status of one objective inside a quest. */
export type ObjectiveStatus = 'done' | 'active' | 'locked'

export interface Objective {
  label: string
  status: ObjectiveStatus
}

export type QuestPath = 'new' | 'migrate'

export interface ColumnQuest {
  table: string
  column: string
  path: QuestPath
  /** Title shown in the quest-log header. */
  title: string
  objectives: Objective[]
  progress: { done: number; total: number }
  /** One-line "what to do next" hint. Empty when the quest is complete. */
  nextMove?: string
  /** True iff every objective is done. */
  complete: boolean
}

export interface QuestLog {
  /** True when `.cipherstash/context.json` exists and parses. False when the
   *  user has not run `stash init`. The renderer surfaces an empty-state
   *  message in that case. */
  initialized: boolean
  /** Whether DB observability succeeded. When false, column quests are
   *  still surfaced (from `migrations.json`) but objective state defaults
   *  to "locked" because we can't tell what's been done. The renderer
   *  shows a footer note. */
  observedFromDb: boolean
  active: ColumnQuest[]
  completed: ColumnQuest[]
}

/** EQL config state for a column. `null` when the column isn't registered. */
export interface EqlColumnSummary {
  state: 'active' | 'pending' | 'encrypting'
}

/**
 * Inputs to {@link buildColumnQuest}. Every field is optional; the builder
 * derives the most accurate objective state it can from whatever is
 * provided. When DB connectivity is missing all of `phase`, `eql`, and
 * `physicalEncryptedTwinExists` should be `undefined`, and the builder
 * produces a quest with all objectives locked.
 */
export interface ColumnObservation {
  table: string
  column: string
  /** From `cs_migrations`. `null` means no events recorded. `undefined`
   *  means the DB couldn't be reached. */
  phase?: MigrationPhase | null
  /** From `eql_v2_configuration`. `null` means not registered. `undefined`
   *  means DB unreachable. */
  eql?: EqlColumnSummary | null
  /** Whether `<column>_encrypted` exists in `information_schema.columns`.
   *  Used as a fallback signal that schema-add has been applied even if
   *  cs_migrations doesn't yet track this column. `undefined` when the
   *  caller can't tell. */
  physicalEncryptedTwinExists?: boolean
}

const MIGRATE_OBJECTIVES = [
  'Schema-add — encrypted twin column added',
  'Dual-writes deployed to production',
  'Backfill historical rows',
  'Cut over to encrypted (rename swap, switch reads)',
  'Drop plaintext column',
]

const NEW_OBJECTIVES = [
  'Schema-add — encrypted column declared and migrated',
  'Live in active EQL config',
]

/**
 * Decide whether a column should be rendered as a migrate quest or a new
 * quest. The discriminator is the encrypted-twin column: if a `<col>_encrypted`
 * column exists physically, the user is migrating an existing populated
 * column (the twin is created alongside the original). Without that signal
 * (and without `cs_migrations` history), default to the new-column shape.
 *
 * When DB connectivity is missing entirely (`phase === undefined`), default
 * to migrate — the 5-objective shape is more informative when we don't know.
 */
export function inferQuestPath(obs: ColumnObservation): QuestPath {
  if (obs.phase === undefined) return 'migrate'
  if (obs.phase !== null) return 'migrate'
  if (obs.physicalEncryptedTwinExists) return 'migrate'
  return 'new'
}

/**
 * Build a column quest from one observation. Pure; no I/O.
 *
 * Migrate-column objective mapping (phase → done count):
 *   null + no EQL              → 0 done, active = "schema-add"
 *   null + EQL pending         → 1 done, active = "dual-writes deployed"
 *   null + encrypted twin only → 1 done, active = "dual-writes deployed"
 *   dual-writing               → 2 done, active = "backfill"
 *   backfilling                → 2 done, active = "backfill"
 *   backfilled                 → 3 done, active = "cut over"
 *   cut-over                   → 4 done, active = "drop plaintext"
 *   dropped                    → 5 done (complete)
 *
 * New-column objective mapping:
 *   no EQL                     → 0 done, active = "schema-add"
 *   EQL pending                → 1 done, active = "promote to active"
 *   EQL active                 → 2 done (complete)
 */
export function buildColumnQuest(obs: ColumnObservation): ColumnQuest {
  const path = inferQuestPath(obs)
  const labels = path === 'migrate' ? MIGRATE_OBJECTIVES : NEW_OBJECTIVES
  const doneCount = computeDoneCount(path, obs)
  const total = labels.length

  const objectives: Objective[] = labels.map((label, idx) => {
    let status: ObjectiveStatus
    if (idx < doneCount) status = 'done'
    else if (idx === doneCount) status = 'active'
    else status = 'locked'

    // When DB is unreachable, we can't be confident about anything past
    // schema-add; mark everything beyond as locked but flag the active
    // one as such.
    if (obs.phase === undefined && obs.eql === undefined) {
      status = 'locked'
    }
    return { label, status }
  })

  // If DB unreachable, no `active` was set above; set the first
  // objective active so the user has *something* to look at.
  if (obs.phase === undefined && obs.eql === undefined) {
    objectives[0] = { ...objectives[0], status: 'active' }
  }

  const complete = doneCount === total

  return {
    table: obs.table,
    column: obs.column,
    path,
    title: titleFor(obs.table, obs.column, path),
    objectives,
    progress: { done: complete ? total : doneCount, total },
    nextMove: complete ? undefined : nextMoveFor(path, doneCount, obs),
    complete,
  }
}

function titleFor(table: string, column: string, path: QuestPath): string {
  return path === 'migrate'
    ? `Encrypt ${table}.${column}`
    : `Add encrypted column ${table}.${column}`
}

function computeDoneCount(path: QuestPath, obs: ColumnObservation): number {
  if (path === 'new') return computeDoneNew(obs)
  return computeDoneMigrate(obs)
}

function computeDoneNew(obs: ColumnObservation): number {
  // Without DB observability, default to 0.
  if (obs.eql === undefined) return 0
  if (obs.eql === null) return 0
  if (obs.eql.state === 'active') return 2
  // Pending or encrypting — schema-add is registered, activation pending.
  return 1
}

function computeDoneMigrate(obs: ColumnObservation): number {
  if (obs.phase === undefined && obs.eql === undefined) return 0

  // Phase progression dominates when we have it.
  switch (obs.phase) {
    case 'dropped':
      return 5
    case 'cut-over':
      return 4
    case 'backfilled':
      return 3
    case 'backfilling':
    case 'dual-writing':
      return 2
    case 'schema-added':
      // Synthesised by some renderers; equivalent to "no events but
      // schema-add has been applied".
      return 1
    case null:
    case undefined:
      // No cs_migrations entry. Look for fallback signals: the encrypted
      // twin column existing in information_schema or the column being
      // registered with EQL counts as schema-add done.
      if (obs.eql || obs.physicalEncryptedTwinExists) return 1
      return 0
  }
}

function nextMoveFor(
  path: QuestPath,
  doneCount: number,
  obs: ColumnObservation,
): string {
  if (path === 'new') {
    if (doneCount === 0) {
      return 'Declare the encrypted column in your schema and run the migration, then `stash db push`.'
    }
    return 'Promote the pending EQL config — `stash db activate`.'
  }

  // Migrate.
  switch (doneCount) {
    case 0:
      return 'Add the encrypted twin column (`<col>_encrypted`) and run the migration.'
    case 1:
      return 'Wire dual-write code on every persistence path, deploy to production, then run `stash encrypt backfill` (it confirms dual-writes and records the event).'
    case 2:
      return `Run \`stash encrypt backfill --table ${obs.table} --column ${obs.column}\` to encrypt historical rows.`
    case 3:
      return `Run \`stash encrypt cutover --table ${obs.table} --column ${obs.column}\` to rename the encrypted twin into place and switch reads.`
    case 4:
      return `Run \`stash encrypt drop --table ${obs.table} --column ${obs.column}\` to remove the plaintext column.`
    default:
      return ''
  }
}

/**
 * Compose a quest log from per-column observations. Pure; no I/O.
 *
 * `initialized` is true when the project has run `stash init` (we have a
 * `context.json`). The renderer uses this to decide whether to show an
 * empty-state quest log. `observedFromDb` is true when at least one
 * observation has live DB data; false if the DB query failed and we're
 * working from manifest alone.
 */
export function buildQuestLog(input: {
  initialized: boolean
  observedFromDb: boolean
  observations: ColumnObservation[]
}): QuestLog {
  const quests = input.observations.map(buildColumnQuest)
  const active: ColumnQuest[] = []
  const completed: ColumnQuest[] = []
  for (const quest of quests) {
    if (quest.complete) completed.push(quest)
    else active.push(quest)
  }
  return {
    initialized: input.initialized,
    observedFromDb: input.observedFromDb,
    active,
    completed,
  }
}
