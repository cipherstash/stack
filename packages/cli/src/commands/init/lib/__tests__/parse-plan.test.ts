import { describe, expect, it } from 'vitest'
import {
  type PlanSummary,
  effectiveStep,
  parsePlanSummary,
  renderPlanSummary,
} from '../parse-plan.js'

describe('parsePlanSummary', () => {
  it('returns undefined when no summary block is present', () => {
    const md = '# CipherStash Encryption Plan\n\nNo summary here.\n'
    expect(parsePlanSummary(md)).toBeUndefined()
  })

  it('parses a well-formed summary block', () => {
    const md = `<!-- cipherstash:plan-summary
{
  "step": "rollout",
  "columns": [
    {"table": "users", "column": "email", "path": "new"},
    {"table": "users", "column": "phone", "path": "migrate"}
  ]
}
-->

# CipherStash Encryption Plan
`
    const summary = parsePlanSummary(md)
    expect(summary).toBeDefined()
    expect(summary?.step).toBe('rollout')
    expect(summary?.columns).toHaveLength(2)
    expect(summary?.columns[0]).toEqual({
      table: 'users',
      column: 'email',
      path: 'new',
    })
  })

  it('treats an absent `step` as legacy `complete` for backwards compat', () => {
    // Plans written before the rollout/cutover split carry no `step` field.
    // They were always end-to-end. effectiveStep falls back to `complete`
    // so existing plans keep working without manual editing.
    const md = `<!-- cipherstash:plan-summary
{"columns": [{"table": "t", "column": "c", "path": "new"}]}
-->`
    const summary = parsePlanSummary(md)
    expect(summary).toBeDefined()
    expect(summary?.step).toBeUndefined()
    expect(effectiveStep(summary as PlanSummary)).toBe('complete')
  })

  it('rejects an unknown `step` value', () => {
    const md = `<!-- cipherstash:plan-summary
{"step": "phase-1", "columns": [{"table": "t", "column": "c", "path": "new"}]}
-->`
    expect(parsePlanSummary(md)).toBeUndefined()
  })

  it('returns undefined for malformed JSON inside the block', () => {
    const md = `<!-- cipherstash:plan-summary
{ not valid json
-->`
    expect(parsePlanSummary(md)).toBeUndefined()
  })

  it('returns undefined when shape does not match (missing columns)', () => {
    const md = `<!-- cipherstash:plan-summary
{"foo": "bar"}
-->`
    expect(parsePlanSummary(md)).toBeUndefined()
  })

  it('rejects entries with an unknown path value', () => {
    const md = `<!-- cipherstash:plan-summary
{"columns": [{"table": "t", "column": "c", "path": "convert-in-place"}]}
-->`
    expect(parsePlanSummary(md)).toBeUndefined()
  })

  it('rejects entries with empty table or column strings', () => {
    const empty = `<!-- cipherstash:plan-summary
{"columns": [{"table": "", "column": "c", "path": "new"}]}
-->`
    expect(parsePlanSummary(empty)).toBeUndefined()
  })

  it('rejects an empty columns array — falls back to soft summary', () => {
    // An agent that writes `{"columns": []}` (genuinely empty plan,
    // truncated write, or chat cutoff) would otherwise render a
    // misleading zero-state line. `stash impl` falls back to the
    // "open it in your editor" panel instead.
    const md = `<!-- cipherstash:plan-summary
{"columns": []}
-->`
    expect(parsePlanSummary(md)).toBeUndefined()
  })

  it('tolerates extra unknown fields without dropping the parse', () => {
    // Future-proofing — agents may include estimated-deploys or other
    // ancillary keys. The parser should ignore them, not fail.
    const md = `<!-- cipherstash:plan-summary
{
  "columns": [{"table": "t", "column": "c", "path": "new"}],
  "estimatedDeploys": 1,
  "notes": "ignore me"
}
-->`
    const summary = parsePlanSummary(md)
    expect(summary?.columns).toHaveLength(1)
  })

  it('finds the block even with surrounding whitespace and extra newlines', () => {
    const md = `

<!--    cipherstash:plan-summary

{
  "step": "cutover",
  "columns": [{"table": "t", "column": "c", "path": "migrate"}]
}

-->

# Plan
`
    const summary = parsePlanSummary(md)
    expect(summary?.step).toBe('cutover')
    expect(summary?.columns[0]?.path).toBe('migrate')
  })
})

describe('renderPlanSummary', () => {
  // Use a recognisable non-npm runner in tests so we can assert that the
  // footer is rendered with whatever `cli` the caller passes in — never
  // hard-codes `npx stash`.
  const CLI = 'pnpm dlx stash'

  function summary(
    columns: PlanSummary['columns'],
    step?: PlanSummary['step'],
  ): PlanSummary {
    return step ? { step, columns } : { columns }
  }

  it('reports column and table counts', () => {
    const out = renderPlanSummary(
      summary([
        { table: 'users', column: 'email', path: 'new' },
        { table: 'users', column: 'phone', path: 'migrate' },
        { table: 'orders', column: 'notes', path: 'migrate' },
      ]),
      CLI,
    )
    expect(out).toContain('3 columns across 2 tables')
  })

  it('uses singular forms when counts are 1', () => {
    const out = renderPlanSummary(
      summary([{ table: 'users', column: 'email', path: 'new' }]),
      CLI,
    )
    expect(out).toContain('1 column across 1 table')
    expect(out).not.toContain('1 columns')
    expect(out).not.toContain('1 tables')
  })

  it('describes each column with its path', () => {
    const out = renderPlanSummary(
      summary([
        { table: 'users', column: 'email', path: 'new' },
        { table: 'users', column: 'phone', path: 'migrate' },
      ]),
      CLI,
    )
    expect(out).toContain('users.email')
    expect(out).toContain('users.phone')
    expect(out).toContain('add new encrypted column')
    expect(out).toContain('migrate existing column')
  })

  it('rollout step: footer mentions deploy gate and uses the caller-supplied runner', () => {
    const out = renderPlanSummary(
      summary(
        [{ table: 'users', column: 'phone', path: 'migrate' }],
        'rollout',
      ),
      CLI,
    )
    expect(out).toMatch(/encryption rollout/i)
    expect(out).toMatch(/deploy/i)
    // The runner prefix is whatever the caller passed — never `npx stash`
    // baked in. This guards the regression where the footer hard-coded
    // `npx` and broke for bun / pnpm / yarn projects.
    expect(out).toContain(`${CLI} status`)
    expect(out).toContain(`${CLI} plan`)
    expect(out).not.toContain('npx stash status')
  })

  it('cutover step: footer mentions backfill, reads switch, and drop', () => {
    const out = renderPlanSummary(
      summary(
        [{ table: 'users', column: 'phone', path: 'migrate' }],
        'cutover',
      ),
      CLI,
    )
    expect(out).toMatch(/encryption cutover/i)
    expect(out).toMatch(/backfill/i)
    expect(out).toMatch(/drop/i)
  })

  it('complete step: footer warns that the deploy gate is skipped', () => {
    const out = renderPlanSummary(
      summary(
        [{ table: 'users', column: 'phone', path: 'migrate' }],
        'complete',
      ),
      CLI,
    )
    expect(out).toMatch(/complete encryption rollout/i)
    expect(out).toMatch(/skips the production-deploy gate/i)
  })

  it('legacy plans without `step`: defaults to complete-rollout footer', () => {
    const out = renderPlanSummary(
      summary([{ table: 'users', column: 'phone', path: 'migrate' }]),
      CLI,
    )
    expect(out).toMatch(/complete encryption rollout/i)
  })

  it('reports a single-deploy implementation when all columns are additive', () => {
    const out = renderPlanSummary(
      summary([
        { table: 'users', column: 'email', path: 'new' },
        { table: 'users', column: 'phone', path: 'new' },
      ]),
      CLI,
    )
    expect(out).toContain('single-deploy')
    expect(out).not.toMatch(/encryption rollout/i)
  })

  it('all-additive plans ignore step (no migrate columns means no rollout split)', () => {
    const out = renderPlanSummary(
      summary([{ table: 'users', column: 'email', path: 'new' }], 'rollout'),
      CLI,
    )
    expect(out).toContain('single-deploy')
  })
})

describe('effectiveStep', () => {
  it('returns the explicit step when set', () => {
    expect(
      effectiveStep({
        step: 'rollout',
        columns: [{ table: 't', column: 'c', path: 'migrate' }],
      }),
    ).toBe('rollout')
    expect(
      effectiveStep({
        step: 'cutover',
        columns: [{ table: 't', column: 'c', path: 'migrate' }],
      }),
    ).toBe('cutover')
  })

  it('falls back to `complete` when step is absent', () => {
    expect(
      effectiveStep({
        columns: [{ table: 't', column: 'c', path: 'migrate' }],
      }),
    ).toBe('complete')
  })
})
