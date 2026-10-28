import { describe, expect, it } from 'vitest'
import { readSelectorJob, selectedJobs } from './lib/selector.mjs'

/**
 * What the selector jobs of the JavaScript and TypeScript workflows decide for
 * a pull request. Each one keeps the paths of the workflow-level filter it
 * replaced, so these pin that nothing was lost in the move.
 */

const WORKFLOWS = {
  tests: '.github/workflows/tests.yml',
  fta: '.github/workflows/fta-v3.yml',
  bench: '.github/workflows/tests-bench.yml',
  supplyChain: '.github/workflows/tests-supply-chain.yml',
  authChangeset: '.github/workflows/require-auth-npm-changeset.yml',
}

/** The jobs a pull request runs, without the two that always run. */
const checks = (relPath, files) =>
  selectedJobs(relPath, files).filter(
    (id) => id !== 'selector' && id !== 'summary',
  )

describe('the JavaScript and TypeScript workflows', () => {
  it.each(Object.values(WORKFLOWS))('%s has a selector job', (relPath) => {
    expect(readSelectorJob(relPath)).not.toBeNull()
  })
})

describe('the Test JS selector', () => {
  const ALL = [
    'e2e-tests',
    'lint',
    'run-tests',
    'run-tests-bun',
    'wasm-e2e-tests',
  ]

  it('runs every job for a change anywhere but the plans', () => {
    expect(checks(WORKFLOWS.tests, ['scripts/example.mjs'])).toEqual(ALL)
    expect(checks(WORKFLOWS.tests, ['docs/example.md'])).toEqual(ALL)
    expect(checks(WORKFLOWS.tests, ['packages/eql/src/v3/a.sql'])).toEqual(ALL)
  })

  it('runs no job for a plan-only change', () => {
    expect(checks(WORKFLOWS.tests, ['docs/plans/nested/example.md'])).toEqual(
      [],
    )
  })
})

describe('the FTA selector', () => {
  it('runs the gate for the analysed sources only', () => {
    const run = (file) => checks(WORKFLOWS.fta, [file])
    expect(
      run('languages/typescript/packages/stack/src/schema/match-defaults.ts'),
    ).toEqual(['fta'])
    expect(
      run('languages/typescript/packages/stack-supabase/src/a.ts'),
    ).toEqual(['fta'])
    expect(run('languages/typescript/packages/stack/src/index.ts')).toEqual([])
  })
})

describe('the bench selector', () => {
  it('runs for the package graph the bench reads', () => {
    const run = (file) => checks(WORKFLOWS.bench, [file])
    expect(
      run('languages/typescript/packages/stack/src/encryption/index.ts'),
    ).toEqual(['tests-bench'])
    expect(run('local/docker-compose.postgres.yml')).toEqual(['tests-bench'])
    expect(run('languages/typescript/packages/stack-prisma/src/a.ts')).toEqual(
      [],
    )
  })
})

describe('the supply chain selector', () => {
  it('runs for the release workflows and the lint, not for other workflows', () => {
    const run = (file) => checks(WORKFLOWS.supplyChain, [file])
    expect(run('.github/workflows/_build-auth-artifacts.yml')).toEqual([
      'verify-no-caching-in-release-workflows',
    ])
    expect(run('scripts/lint-no-workflow-caching.mjs')).toEqual([
      'verify-no-caching-in-release-workflows',
    ])
    expect(run('.github/workflows/tests.yml')).toEqual([])
  })
})

describe('the auth changeset selector', () => {
  it('runs for what @cipherstash/auth ships', () => {
    const run = (file) => checks(WORKFLOWS.authChangeset, [file])
    expect(run('packages/stack-auth/src/lib.rs')).toEqual([
      'require-npm-changeset',
    ])
    expect(run('languages/typescript/packages/auth/index.js')).toEqual([
      'require-npm-changeset',
    ])
    expect(run('packages/stack-auth/tasks.toml')).toEqual([])
  })
})
