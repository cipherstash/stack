/**
 * Parse and render `.cipherstash/plan.md` summary blocks.
 *
 * The agent is instructed (in `renderPlanPrompt`) to begin the plan file
 * with an HTML-comment block carrying a structured JSON summary:
 *
 *   <!-- cipherstash:plan-summary
 *   {
 *     "step": "rollout",
 *     "columns": [
 *       {"table": "users", "column": "email", "path": "new"},
 *       {"table": "users", "column": "phone", "path": "migrate"}
 *     ]
 *   }
 *   -->
 *
 * `step` (optional for backwards compatibility) tells `stash impl` which
 * scope of the encryption rollout this plan covers:
 *   - `"rollout"`   — schema-add + dual-write code + db push (pending).
 *                     Deploy gate after this; cutover comes in a later run.
 *   - `"cutover"`   — backfill + cutover + drop. Requires `dual_writing`
 *                     events in `cs_migrations`; impl refuses otherwise.
 *   - `"complete"`  — the whole lifecycle in one document (escape hatch
 *                     for users without a production-deploy to gate on).
 *
 * Plans without `step` are treated as `"complete"` for backwards
 * compatibility — that is how every plan was shaped before the rollout
 * split landed. Plans without the block (or with a malformed one) fall
 * back to a soft "open the plan in your editor" message — never an error.
 */

export type PlanPath = 'new' | 'migrate'

export type PlanStep = 'rollout' | 'cutover' | 'complete'

export interface PlanColumn {
  table: string
  column: string
  path: PlanPath
}

export interface PlanSummary {
  /** Scope of this plan. Optional for backwards compat; absent = `complete`. */
  step?: PlanStep
  columns: PlanColumn[]
}

const SUMMARY_BLOCK_RE = /<!--\s*cipherstash:plan-summary\s*([\s\S]*?)\s*-->/

function isPlanColumn(x: unknown): x is PlanColumn {
  if (!x || typeof x !== 'object') return false
  const c = x as Record<string, unknown>
  return (
    typeof c.table === 'string' &&
    c.table.length > 0 &&
    typeof c.column === 'string' &&
    c.column.length > 0 &&
    (c.path === 'new' || c.path === 'migrate')
  )
}

function isPlanStep(x: unknown): x is PlanStep {
  return x === 'rollout' || x === 'cutover' || x === 'complete'
}

function isPlanSummary(x: unknown): x is PlanSummary {
  if (!x || typeof x !== 'object') return false
  const obj = x as Record<string, unknown>
  // Empty `columns` is rejected: downstream `renderPlanSummary` would
  // produce a misleading zero-state line. `stash impl` falls back to the
  // soft "open it in your editor" panel instead.
  if (
    !Array.isArray(obj.columns) ||
    obj.columns.length === 0 ||
    !obj.columns.every(isPlanColumn)
  ) {
    return false
  }
  if (obj.step !== undefined && !isPlanStep(obj.step)) return false
  return true
}

/**
 * Extract the machine-readable plan summary, or `undefined` if the plan
 * has no summary block (or one that doesn't match the schema). Never
 * throws — malformed input is treated as "no summary."
 */
export function parsePlanSummary(content: string): PlanSummary | undefined {
  const match = content.match(SUMMARY_BLOCK_RE)
  if (!match) return undefined
  try {
    const parsed = JSON.parse(match[1]) as unknown
    if (!isPlanSummary(parsed)) return undefined
    return parsed
  } catch {
    return undefined
  }
}

/** Resolve `step` with the legacy default. Plans pre-dating the split
 *  carry no `step` and were always end-to-end. */
export function effectiveStep(summary: PlanSummary): PlanStep {
  return summary.step ?? 'complete'
}

const COLUMN_LABEL_WIDTH = 20

/**
 * Render the plan summary as the body of a `p.note` panel.
 *
 *   3 columns across 2 tables
 *
 *   ◇ users.email          add new encrypted column
 *   ◇ users.phone          migrate existing column
 *   ◇ orders.notes         migrate existing column
 *
 *   Encryption rollout — implementation lands schema-add and dual-write
 *   code in your repo. Deploy that to production, verify with
 *   `npx stash status`, then run `npx stash plan` again to draft the
 *   encryption cutover.
 *
 * Footer copy varies by step:
 *   - rollout   → "Encryption rollout — deploy gate next."
 *   - cutover   → "Encryption cutover — backfill, switch reads, drop plaintext."
 *   - complete  → "Complete rollout — skips the deploy gate; only safe when
 *                 this database is not backing a deployed application."
 *   - (no migrate columns) → "All columns are additive — single-deploy."
 */
export function renderPlanSummary(summary: PlanSummary): string {
  const tables = new Set(summary.columns.map((c) => c.table))
  const migrateCount = summary.columns.filter(
    (c) => c.path === 'migrate',
  ).length

  const colCount = summary.columns.length
  const tableCount = tables.size

  const header = `${colCount} column${colCount === 1 ? '' : 's'} across ${tableCount} table${tableCount === 1 ? '' : 's'}`

  const rows = summary.columns.map((c) => {
    const desc =
      c.path === 'new' ? 'add new encrypted column' : 'migrate existing column'
    return `◇ ${`${c.table}.${c.column}`.padEnd(COLUMN_LABEL_WIDTH)} ${desc}`
  })

  const footer = renderFooter(effectiveStep(summary), migrateCount)

  return [header, '', ...rows, '', footer].join('\n')
}

function renderFooter(step: PlanStep, migrateCount: number): string {
  if (migrateCount === 0) {
    return 'All columns are additive — single-deploy implementation.'
  }
  switch (step) {
    case 'rollout':
      return 'Encryption rollout — implementation lands schema-add and dual-write code in your repo. Deploy that to production, verify with `npx stash status`, then run `npx stash plan` again to draft the encryption cutover.'
    case 'cutover':
      return 'Encryption cutover — implementation runs the backfill, switches reads to encrypted, and drops plaintext. Requires dual-writes already live in production.'
    case 'complete':
      return 'Complete encryption rollout — covers schema-add through drop in one go. Skips the production-deploy gate; only safe when this database is not backing a deployed application.'
  }
}
