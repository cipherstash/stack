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
  /** One-line "what to do next" hint. Empty when the quest is complete
   *  (i.e. when `progress.done === progress.total`). */
  nextMove?: string
}

/** A quest is complete when every objective has been done. */
export function isComplete(quest: ColumnQuest): boolean {
  return quest.progress.done === quest.progress.total
}

export interface QuestLog {
  /** True when `.cipherstash/context.json` exists and parses. False when the
   *  user has not run `stash init`. The renderer surfaces an empty-state
   *  message in that case. */
  initialized: boolean
  /** True when `.cipherstash/plan.md` exists. The plan is a markdown
   *  document drafted by the planning agent — it is *not* the same as the
   *  manifest (`migrations.json`), which only fills in once migrations
   *  actually run. When `planExists` is true but no quests have been
   *  derived from the manifest, the empty-state message points the user
   *  at `stash impl` instead of `stash plan`. */
  planExists: boolean
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
  /** The column's EQL generation, from the manifest's cached `eqlVersion`.
   *  v3 has a 4-objective ladder (no cut-over rename — the app switches to
   *  the encrypted column by name). `undefined` (unknown / pre-v3 manifest)
   *  renders the v2 ladder. */
  eqlVersion?: 2 | 3
}

const MIGRATE_OBJECTIVES = [
  'Schema-add — encrypted twin column added',
  'Dual-writes deployed to production',
  'Backfill historical rows',
  'Cut over to encrypted (rename swap, switch reads)',
  'Drop plaintext column',
]

// EQL v3 has no cut-over: configuration lives in the column's own domain
// type, so the app switches to the encrypted column BY NAME and the
// plaintext column is dropped straight after backfill.
const MIGRATE_OBJECTIVES_V3 = [
  'Schema-add — encrypted column added',
  'Dual-writes deployed to production',
  'Backfill historical rows',
  'Switch app to the encrypted column, then drop plaintext',
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
 * `cli` is interpolated into the `nextMove` hint so the user sees
 * commands prefixed with their actual package-manager runner — pass
 * `runnerCommand(pm, 'stash')` rather than a hard-coded `npx stash`.
 */
export function buildColumnQuest(
  obs: ColumnObservation,
  cli: string,
): ColumnQuest {
  const path = inferQuestPath(obs)
  const labels =
    path === 'migrate'
      ? obs.eqlVersion === 3
        ? MIGRATE_OBJECTIVES_V3
        : MIGRATE_OBJECTIVES
      : NEW_OBJECTIVES
  const total = labels.length
  const doneCount = computeDoneCount(path, obs)
  const dbUnreachable = obs.phase === undefined && obs.eql === undefined

  // When the DB is unreachable we can't claim any objective is done.
  // Surface the first objective as active (so the user sees the rollout
  // exists) and lock the rest; the renderer adds the "DB unreachable"
  // footnote that explains the missing observation.
  const objectives: Objective[] = labels.map((label, idx) => ({
    label,
    status: dbUnreachable
      ? idx === 0
        ? 'active'
        : 'locked'
      : idx < doneCount
        ? 'done'
        : idx === doneCount
          ? 'active'
          : 'locked',
  }))

  const complete = doneCount === total

  // Without a live DB observation we cannot trust `doneCount` — it falls
  // back to 0, but a column mid-cutover would still appear "0/5" here.
  // Suppressing `nextMove` avoids confidently telling the user to re-run
  // schema-add (or any other phase-zero action) when the actual state is
  // unknown. The renderer's "could not reach the database" footer is the
  // honest answer for what to do next.
  const nextMove =
    complete || dbUnreachable
      ? undefined
      : nextMoveFor(path, doneCount, obs, cli)

  return {
    table: obs.table,
    column: obs.column,
    path,
    title: titleFor(obs.table, obs.column, path),
    objectives,
    progress: { done: doneCount, total },
    nextMove,
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

  const isV3 = obs.eqlVersion === 3

  // Phase progression dominates when we have it. The v3 ladder is one rung
  // shorter (no cut-over), so its terminal phases map one lower.
  switch (obs.phase) {
    case 'dropped':
      return isV3 ? 4 : 5
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
  cli: string,
): string {
  if (path === 'new') {
    if (doneCount === 0) {
      return 'Declare the encrypted column in your schema and run the migration.'
    }
    return `Promote the pending EQL config — \`${cli} db activate\`.`
  }

  // Migrate. The v3 ladder has no cut-over — after backfill the app
  // switches to the encrypted column by name, then drops the plaintext.
  if (obs.eqlVersion === 3) {
    switch (doneCount) {
      case 0:
        return 'Add the encrypted column and run the migration.'
      case 1:
        return `Wire dual-write code on every persistence path, deploy to production, then run \`${cli} encrypt backfill\` (it confirms dual-writes and records the event).`
      case 2:
        return `Run \`${cli} encrypt backfill --table ${obs.table} --column ${obs.column}\` to encrypt historical rows.`
      case 3:
        return `Point your application at the encrypted column (update schema/queries — EQL v3 has no rename step), verify reads, then run \`${cli} encrypt drop --table ${obs.table} --column ${obs.column}\`.`
      default:
        return ''
    }
  }

  switch (doneCount) {
    case 0:
      return 'Add the encrypted twin column (`<col>_encrypted`) and run the migration.'
    case 1:
      return `Wire dual-write code on every persistence path, deploy to production, then run \`${cli} encrypt backfill\` (it confirms dual-writes and records the event).`
    case 2:
      return `Run \`${cli} encrypt backfill --table ${obs.table} --column ${obs.column}\` to encrypt historical rows.`
    case 3:
      return `Run \`${cli} encrypt cutover --table ${obs.table} --column ${obs.column}\` to rename the encrypted twin into place and switch reads.`
    case 4:
      return `Run \`${cli} encrypt drop --table ${obs.table} --column ${obs.column}\` to remove the plaintext column.`
    default:
      return ''
  }
}

/**
 * Compose a quest log from per-column observations. Pure; no I/O.
 *
 * `initialized` is true when the project has run `stash init` (we have a
 * `context.json`). `planExists` is true when `.cipherstash/plan.md` has
 * been drafted by the planning agent — together with an empty quest list,
 * this is what disambiguates "user hasn't planned yet" (point at `plan`)
 * from "plan is drafted but not yet executed" (point at `impl`).
 * `observedFromDb` is true when at least one observation has live DB
 * data; false if the DB query failed and we're working from manifest
 * alone. `cli` is the package-manager-aware command prefix passed
 * through to per-quest `nextMove` hints.
 */
export function buildQuestLog(input: {
  initialized: boolean
  planExists: boolean
  observedFromDb: boolean
  observations: ColumnObservation[]
  cli: string
}): QuestLog {
  const quests = input.observations.map((obs) =>
    buildColumnQuest(obs, input.cli),
  )
  const active: ColumnQuest[] = []
  const completed: ColumnQuest[] = []
  for (const quest of quests) {
    if (isComplete(quest)) completed.push(quest)
    else active.push(quest)
  }
  return {
    initialized: input.initialized,
    planExists: input.planExists,
    observedFromDb: input.observedFromDb,
    active,
    completed,
  }
}
