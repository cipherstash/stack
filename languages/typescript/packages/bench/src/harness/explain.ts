import type pg from 'pg'

export type PlanNode = {
  'Node Type': string
  'Index Name'?: string
  'Relation Name'?: string
  'Actual Total Time'?: number
  'Total Cost'?: number
  Plans?: PlanNode[]
} & Record<string, unknown>

type ExplainRow = { 'QUERY PLAN': [{ Plan: PlanNode }] }

export type ExplainOptions = {
  analyze?: boolean
  buffers?: boolean
}

/**
 * Run EXPLAIN with FORMAT JSON and return the top-level plan node.
 * Pass `analyze: false` for cheaper plan-shape checks that don't actually
 * execute the query.
 */
export async function explain(
  client: pg.Client,
  sql: string,
  params: unknown[] = [],
  options: ExplainOptions = {},
): Promise<PlanNode> {
  const { analyze = true, buffers = true } = options
  const flags = [
    analyze ? 'ANALYZE' : null,
    buffers && analyze ? 'BUFFERS' : null,
    'FORMAT JSON',
  ]
    .filter(Boolean)
    .join(', ')

  const res = await client.query<ExplainRow>(
    `EXPLAIN (${flags}) ${sql}`,
    params as never[],
  )
  return res.rows[0]['QUERY PLAN'][0].Plan
}

export function walk(plan: PlanNode): PlanNode[] {
  const out: PlanNode[] = []
  const stack: PlanNode[] = [plan]
  while (stack.length > 0) {
    const next = stack.pop()
    if (!next) break
    out.push(next)
    if (next.Plans) stack.push(...next.Plans)
  }
  return out
}

export function findNode(
  plan: PlanNode,
  predicate: (n: PlanNode) => boolean,
): PlanNode | null {
  for (const node of walk(plan)) {
    if (predicate(node)) return node
  }
  return null
}

export function hasNodeType(plan: PlanNode, nodeType: string): boolean {
  return findNode(plan, (n) => n['Node Type'] === nodeType) !== null
}

export function hasSeqScan(plan: PlanNode): boolean {
  return walk(plan).some(
    (n) =>
      (n['Node Type'] === 'Seq Scan' ||
        n['Node Type'] === 'Parallel Seq Scan') &&
      n['Relation Name'] === 'bench',
  )
}

export function usesIndex(plan: PlanNode, indexName: string): boolean {
  return findNode(plan, (n) => n['Index Name'] === indexName) !== null
}

/**
 * Returns the first scan node touching the bench table — useful for printing
 * a one-line plan summary in #422 investigation tests.
 */
export function topScan(plan: PlanNode): PlanNode | null {
  return findNode(
    plan,
    (n) =>
      typeof n['Node Type'] === 'string' &&
      /Scan/.test(n['Node Type']) &&
      n['Relation Name'] === 'bench',
  )
}

export function summarize(plan: PlanNode): string {
  const scan = topScan(plan)
  if (!scan) return plan['Node Type']
  const idx = scan['Index Name'] ? ` on ${scan['Index Name']}` : ''
  return `${scan['Node Type']}${idx}`
}
