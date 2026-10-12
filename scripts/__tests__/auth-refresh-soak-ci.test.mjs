import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const runner = './.github/workflows/_test-auth-refresh-soak.yml'
const prs = readWorkflow('.github/workflows/tests-auth-refresh.yml')
const release = readWorkflow('.github/workflows/release-plz.yml')
const soak = readWorkflow(runner)

describe('auth refresh cancellation soak gates', () => {
  it('runs the short soak on every PR without a path or branch filter', () => {
    expect(prs.on.pull_request).toEqual({})
    expect(prs.jobs.short.uses).toBe(runner)
    expect(prs.jobs.short.if).toBeUndefined()
    expect(soak.on.workflow_call.inputs.long.default).toBe(false)
    const short = soak.jobs.soak.steps.find(
      (step) => step.name === 'Short seeded soak',
    )
    expect(short.run).toContain('test(cancellation_soak_short)')
    expect(short['continue-on-error']).toBeUndefined()
  })

  it('runs the long soak on Version Packages and refresher changes', () => {
    expect(prs.jobs.long.uses).toBe(runner)
    expect(prs.jobs.long.with.long).toBe(true)
    expect(prs.jobs.long.if).toContain(
      "github.head_ref == 'changeset-release/main'",
    )
    expect(prs.jobs.long.if).toContain(
      "needs.changes.outputs.refresh == 'true'",
    )
    const paths = prs.jobs.changes.steps.find((step) => step.id === 'paths')
    expect(paths.with.filters).toContain("'packages/stack-auth/**'")
  })

  it('requires a successful long soak before publishing stack-auth', () => {
    const gate = release.jobs['auth-refresh-soak']
    expect(
      gate.steps.find((step) => step.name === 'Long seeded soak').run,
    ).toBe('mise run test:soak:stack-auth')
    expect(gate.if).toBeUndefined()
    expect(release.jobs['release-crates'].needs).toContain('auth-refresh-soak')
    // No status function bypasses the implicit success() dependency check.
    expect(release.jobs['release-crates'].if).not.toMatch(
      /always\(|cancelled\(|failure\(/,
    )
  })

  it('actually selects the ignored long test and propagates failures', () => {
    const long = soak.jobs.soak.steps.find(
      (step) => step.name === 'Long seeded soak',
    )
    expect(long.run).toBe('mise run test:soak:stack-auth')
    expect(long['continue-on-error']).toBeUndefined()
    const tasks = readFileSync(
      join(REPO_ROOT, 'packages/stack-auth/tasks.toml'),
      'utf8',
    )
    const task = tasks.split('["test:soak:stack-auth"]')[1].split('\n[')[0]
    expect(task).toContain('--run-ignored ignored-only')
    expect(task).toContain('test(cancellation_soak_long)')
    expect(task).not.toContain('|| true')
  })
})
