/**
 * Parse and render `.cipherstash/plan.md` summary blocks.
 *
 * The agent embeds an HTML-comment header at the top of the plan file
 * carrying a JSON summary that `stash impl` parses. Plans without the
 * block fall back to a soft "open it in your editor" message — never
 * an error. `step` is optional for backwards compat: plans pre-dating
 * the rollout/cutover split had no step field and were always
 * end-to-end, so missing `step` is treated as `"complete"`.
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
 * Render the plan summary as the body of a `p.note` panel. The `cli`
 * argument is the package-manager-aware command prefix (e.g. `pnpm dlx
 * stash` / `bunx stash` / `npx stash`) — pass `runnerCommand(pm, 'stash')`
 * so the rendered footer uses the runner the user actually invokes.
 *
 *   3 columns across 2 tables
 *
 *   ◇ users.email          add new encrypted column
 *   ◇ users.phone          migrate existing column
 *   ◇ orders.notes         migrate existing column
 *
 *   Encryption rollout — implementation lands schema-add and dual-write
 *   code in your repo. Deploy that to production, verify with
 *   `<runner> stash status`, then run `<runner> stash plan` again to
 *   draft the encryption cutover.
 *
 * Footer copy varies by step:
 *   - rollout   → next-step pointer at the deploy gate.
 *   - cutover   → backfill / switch reads / drop plaintext summary.
 *   - complete  → loud "skips the deploy gate" warning.
 *   - (no migrate columns) → "single-deploy" line.
 */
export function renderPlanSummary(summary: PlanSummary, cli: string): string {
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

  const footer = renderFooter(effectiveStep(summary), migrateCount, cli)

  return [header, '', ...rows, '', footer].join('\n')
}

function renderFooter(
  step: PlanStep,
  migrateCount: number,
  cli: string,
): string {
  if (migrateCount === 0) {
    return 'All columns are additive — single-deploy implementation.'
  }
  switch (step) {
    case 'rollout':
      return `Encryption rollout — implementation lands schema-add and dual-write code in your repo. Deploy that to production, verify with \`${cli} status\`, then run \`${cli} plan\` again to draft the encryption cutover.`
    case 'cutover':
      return 'Encryption cutover — implementation runs the backfill, switches reads to encrypted, and drops plaintext. Requires dual-writes already live in production.'
    case 'complete':
      return 'Complete encryption rollout — covers schema-add through drop in one go. Skips the production-deploy gate; only safe when this database is not backing a deployed application.'
  }
}
