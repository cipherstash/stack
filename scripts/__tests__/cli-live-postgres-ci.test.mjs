import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { readJsonc } from './lib/read-jsonc.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

describe('CLI live-Postgres CI contract', () => {
  it('forwards the live database URL through Turbo test tasks', () => {
    const turbo = readJsonc(join(REPO_ROOT, 'turbo.json'))

    expect(turbo.tasks.test.env).toContain('STASH_TEST_DATABASE_URL')
  })

  it('supplies the live database URL from the test workflow', () => {
    const workflow = readWorkflow('.github/workflows/tests.yml')
    const runTests = workflow.jobs['run-tests'].steps.find(
      (step) => step.name === 'Run tests',
    )

    expect(runTests.env.STASH_TEST_DATABASE_URL).toMatch(
      /^postgres:\/\/[^/]+\/cipherstash$/,
    )
  })

  it('runs the live reinstall suite against both pre-17 and current Postgres catalogs', () => {
    const workflow = readWorkflow('.github/workflows/tests.yml')
    const runTests = workflow.jobs['run-tests']
    const versions = runTests.strategy.matrix['postgres-version']

    expect(versions).toEqual([16, 17])
    expect(runTests.strategy.matrix['node-version']).toEqual([22, 24])
    expect(runTests.strategy.matrix.exclude).toEqual([
      { 'node-version': 22, 'postgres-version': 17 },
      { 'node-version': 24, 'postgres-version': 16 },
    ])
    expect(runTests.services.postgres.image).toContain(
      '$' + '{{ matrix.postgres-version }}',
    )
  })

  it('serializes live suites that share the EQL schemas', async () => {
    const config = await import(
      '../../packages/cli/vitest.config.ts?cli-live-ci-contract'
    )
    const live = config.default.test.projects.find(
      (project) => project.test.name === 'live',
    )

    expect(live.test.poolOptions.forks.singleFork).toBe(true)
  })
})
