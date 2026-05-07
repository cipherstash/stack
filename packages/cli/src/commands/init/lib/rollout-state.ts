import { type MigrationPhase, latestByColumn } from '@cipherstash/migrate'
import pg from 'pg'

/**
 * What rollout work this column needs next, derived from `cs_migrations`.
 *
 * - `rollout`   — schema-add and dual-write code aren't confirmed live yet.
 *                 No `dual_writing` event recorded; the deploy gate hasn't
 *                 been crossed.
 * - `cutover`   — `dual_writing` (or later) is recorded. Backfill, cutover,
 *                 and drop are the remaining work.
 * - `completed` — `dropped` event recorded; nothing left to do.
 * - `unknown`   — column has no `cs_migrations` entries. Could be a brand
 *                 new column, a migrate column that hasn't started yet, or
 *                 a column where init-side work is still in progress.
 *                 Callers should treat this as "needs the user to confirm
 *                 path=new vs path=migrate".
 */
export type ColumnNeeds = 'rollout' | 'cutover' | 'completed' | 'unknown'

export interface ColumnState {
  table: string
  column: string
  /** Latest phase recorded for this column, or `null` if no events. */
  phase: MigrationPhase | null
  needs: ColumnNeeds
}

/**
 * Classify a phase into the next plan-step the column needs. The mapping is:
 *
 *   null            → unknown   (no events; brand new or not started)
 *   schema-added    → rollout   (synthesised in some renderers; safe default)
 *   dual-writing    → cutover   (deploy gate crossed)
 *   backfilling     → cutover   (cutover work in flight)
 *   backfilled      → cutover   (ready to rename swap)
 *   cut-over        → cutover   (rename done; drop still pending)
 *   dropped         → completed (lifecycle complete)
 */
export function classifyPhase(phase: MigrationPhase | null): ColumnNeeds {
  if (phase === null) return 'unknown'
  if (phase === 'schema-added') return 'rollout'
  if (phase === 'dropped') return 'completed'
  return 'cutover'
}

/**
 * Read `cs_migrations` once and classify a list of (table, column) pairs.
 * Used by `stash plan` to dispatch to the right template, by `stash impl`
 * to enforce the deploy gate, and by `stash status` (the quest log) to
 * shape per-column objective state.
 *
 * Connects, queries, and disconnects in one call. Callers that already
 * have a connection should use `classifyPhases` against the result of
 * `latestByColumn` directly.
 *
 * On any unexpected error, returns `unknown` for every input — never
 * throws. The encryption rollout is paused-by-default safer than
 * crashed-by-default.
 */
export async function detectColumnStates(
  databaseUrl: string,
  columns: ReadonlyArray<{ table: string; column: string }>,
): Promise<ColumnState[]> {
  if (columns.length === 0) return []

  const client = new pg.Client({ connectionString: databaseUrl })
  try {
    await client.connect()
    const events = await latestByColumnSafe(client)
    return classifyPhases(columns, (table, column) => {
      const row = events.get(`${table}.${column}`)
      return row?.phase ?? null
    })
  } catch {
    return columns.map((c) => ({
      table: c.table,
      column: c.column,
      phase: null,
      needs: 'unknown' as const,
    }))
  } finally {
    await client.end().catch(() => undefined)
  }
}

/**
 * Pure classification helper. Given a phase lookup function, return one
 * `ColumnState` per requested column. Useful when the caller already has
 * an open pg connection (`stash status` reads three things in parallel).
 */
export function classifyPhases(
  columns: ReadonlyArray<{ table: string; column: string }>,
  lookup: (table: string, column: string) => MigrationPhase | null,
): ColumnState[] {
  return columns.map((c) => {
    const phase = lookup(c.table, c.column)
    return {
      table: c.table,
      column: c.column,
      phase,
      needs: classifyPhase(phase),
    }
  })
}

/**
 * Roll a list of per-column needs up into a single plan step. The
 * dispatch rule for `stash plan`:
 *
 *   any cutover  → plan the cutover (covers any rollout-state columns
 *                  along the way; agent will batch them)
 *   any rollout  → plan the rollout
 *   all completed → no work to plan
 *   otherwise    → unknown (caller asks the user to choose)
 *
 * The bias toward cutover when mixed is deliberate: if any column has
 * passed the deploy gate, the user has acknowledged dual-writes are live.
 * The cutover plan template explicitly handles "and these other columns
 * still need their rollout work too" alongside the destructive steps.
 */
export function rollupPlanStep(
  states: ReadonlyArray<ColumnState>,
): 'rollout' | 'cutover' | 'completed' | 'unknown' {
  if (states.length === 0) return 'unknown'
  if (states.some((s) => s.needs === 'cutover')) return 'cutover'
  if (states.some((s) => s.needs === 'rollout')) return 'rollout'
  if (states.every((s) => s.needs === 'completed')) return 'completed'
  return 'unknown'
}

async function latestByColumnSafe(client: pg.Client) {
  try {
    return await latestByColumn(client)
  } catch (err) {
    // The cs_migrations table may not exist yet (project that has run
    // `stash init` but not `stash db install`, or a fresh database).
    // Treat as "no events" rather than a hard error.
    if (
      err instanceof Error &&
      /cs_migrations|schema "cipherstash"/i.test(err.message)
    ) {
      return new Map()
    }
    throw err
  }
}
