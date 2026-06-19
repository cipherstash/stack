import type { MigrationPhase } from '@cipherstash/migrate'
import pg from 'pg'
import { latestByColumnSafe } from '../../encrypt/lib/db-readers.js'

/** Conservative connect timeout for rollout-state lookups: the CLI
 *  surfaces these on hot paths (`stash plan`, `stash impl`, `stash
 *  status`), and pg's default of "no timeout" lets an unreachable host
 *  hang on the OS-level TCP timeout (~75s on most platforms). */
const CONNECT_TIMEOUT_MS = 5_000

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

/** Classify a phase into the plan-step the column needs next. */
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
 * Returns `null` on connect / query failure. Callers must distinguish
 * `null` ("could not observe") from a populated array containing
 * `needs: 'unknown'` rows ("observed, but no events recorded for this
 * column"). Conflating the two would let a transient DB outage masquerade
 * as "rollout has not started" — and `verifyCutoverPreconditions` then
 * blocks legitimate cutover work with a misleading "no `dual_writing`
 * event" error.
 */
export async function detectColumnStates(
  databaseUrl: string,
  columns: ReadonlyArray<{ table: string; column: string }>,
): Promise<ColumnState[] | null> {
  if (columns.length === 0) return []

  const client = new pg.Client({
    connectionString: databaseUrl,
    connectionTimeoutMillis: CONNECT_TIMEOUT_MS,
  })
  try {
    await client.connect()
    const events = await latestByColumnSafe(client)
    return classifyPhases(columns, (table, column) => {
      const row = events.get(`${table}.${column}`)
      return row?.phase ?? null
    })
  } catch {
    return null
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
