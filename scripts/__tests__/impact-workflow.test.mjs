import { describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

const workflowPath = '.github/workflows/impact.yml'

describe('advisory change impact', () => {
  it('applies every generated-output exclusion to both report scopes', () => {
    const all = readWorkflow('.github/impact-gate/all.yml')
    const source = readWorkflow('.github/impact-gate/source.yml')
    expect(source.ignore).toEqual(expect.arrayContaining(all.ignore))
  })

  it('reports every pull request and refreshes main with read-only permissions', () => {
    const workflow = readWorkflow(workflowPath)
    expect(workflow.on).toEqual({
      pull_request: null,
      push: { branches: ['main'] },
    })
    expect(workflow.permissions).toEqual({ contents: 'read' })
    const job = workflow.jobs.impact
    expect(job.permissions).toBeUndefined()
    expect(job.needs).toBeUndefined()
    const checkout = job.steps.find((step) =>
      step.uses?.startsWith('actions/checkout@'),
    )
    expect(checkout.with).toMatchObject({
      'fetch-depth': 0,
      'persist-credentials': false,
    })
  })

  it('keeps baseline caches compatible and saves only main-push results', () => {
    const job = readWorkflow(workflowPath).jobs.impact
    const restore = job.steps.find((step) =>
      step.uses?.startsWith('actions/cache/restore@'),
    )
    expect(restore).toBeDefined()
    expect(restore.with.key).toContain('hashFiles(')
    expect(restore.with.key).toContain("'.github/impact-gate/**'")
    expect(restore.with.key).toContain("'scripts/impact-gate.py'")
    expect(restore.with.key).toContain("'.github/workflows/impact.yml'")
    expect(restore.with.key).toContain('steps.target.outputs.key')
    expect(restore.with.key).toContain(
      'github.event.pull_request.base.sha || github.sha',
    )
    expect(restore.with['restore-keys']).toBe(
      restore.with.key.replace(
        // biome-ignore lint/suspicious/noTemplateCurlyInString: literal Actions expression
        '-${{ github.event.pull_request.base.sha || github.sha }}',
        '-',
      ),
    )
    const save = job.steps.find((step) =>
      step.uses?.startsWith('actions/cache/save@'),
    )
    expect(save.if).toBe(
      "github.event_name == 'push' && steps.prepare.outputs.rebuilt == 'true'",
    )
    expect(save.with.path).toBe(restore.with.path)
  })

  it('runs the real-CLI checks and reports PRs without masking tool errors', () => {
    const job = readWorkflow(workflowPath).jobs.impact
    const checks = job.steps.find((step) =>
      step.run?.includes('unittest discover'),
    )
    expect(checks).toBeDefined()
    const report = job.steps.find((step) =>
      step.run?.includes('scripts/impact-gate.py report'),
    )
    expect(report).toBeDefined()
    expect(report.if).toBe("github.event_name == 'pull_request'")
    expect(report.run).toContain('--base "$BASE_REF"')
    expect(report.run).toContain('--cache-dir "$BASELINE_DIR"')
    expect(report.run).not.toMatch(/\|\||\|\s*tee/)
    expect(job.env.BASE_REF).toContain('github.base_ref')
    expect(job['continue-on-error']).toBeUndefined()
    expect(job.steps.every((step) => !step['continue-on-error'])).toBe(true)
    expect(
      job.steps.some((step) => step.uses?.startsWith('officefloor/')),
    ).toBe(false)
    expect(job.steps.some((step) => step.run?.includes('pnpm install'))).toBe(
      false,
    )
    expect(job.defaults.run.shell).toBe('bash')
  })
})
