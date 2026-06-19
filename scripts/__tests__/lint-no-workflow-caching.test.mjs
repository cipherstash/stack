import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'

// Workflows the supply-chain gate is responsible for.
const TARGET_WORKFLOWS = [
  '.github/workflows/release.yml',
  '.github/workflows/tests-supply-chain.yml',
]

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-workflow-caching.mjs',
)
const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

function run(...targets) {
  try {
    execFileSync('node', [SCRIPT, ...targets], { encoding: 'utf8' })
    return { exitCode: 0, output: '' }
  } catch (err) {
    return {
      exitCode: err.status,
      output: String(err.stdout) + String(err.stderr),
    }
  }
}

describe('lint-no-workflow-caching', () => {
  const fx = (name) =>
    resolve(
      fileURLToPath(import.meta.url),
      `../fixtures/lint-no-workflow-caching/${name}`,
    )

  it('defaults to checking release.yml and tests-supply-chain.yml', () => {
    expect(run().exitCode).toBe(0)
  })

  it('passes on a workflow with no caching', () => {
    expect(run(fx('clean.yml')).exitCode).toBe(0)
  })

  it('fails on `cache:` under a setup-node step', () => {
    const r = run(fx('setup-node-cache.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/with\.cache/)
  })

  it('fails on an `actions/cache` step', () => {
    const r = run(fx('actions-cache.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/actions\/cache@/)
  })

  it('fails on an `actions/cache/restore` step', () => {
    const r = run(fx('actions-cache-restore.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/actions\/cache\/restore@/)
  })

  it('fails on an `actions/cache/save` step', () => {
    const r = run(fx('actions-cache-save.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/actions\/cache\/save@/)
  })

  it('passes when `actions/cache` appears only as prose, not a step', () => {
    expect(run(fx('no-actions-cache.yml')).exitCode).toBe(0)
  })

  it('fails when caching is not disabled explicitly', () => {
    const r = run(fx('missing-explicit-false.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/\bcache\b/)
    expect(r.output).toMatch(/package-manager-cache/)
  })

  it('keeps release.yml free of GitHub Actions caching', () => {
    expect(
      run(resolve(REPO_ROOT, '.github/workflows/release.yml')).exitCode,
    ).toBe(0)
  })

  it('keeps tests-supply-chain.yml free of GitHub Actions caching', () => {
    expect(
      run(resolve(REPO_ROOT, '.github/workflows/tests-supply-chain.yml'))
        .exitCode,
    ).toBe(0)
  })

  it('the target workflows contain no `actions/cache` step', () => {
    for (const target of TARGET_WORKFLOWS) {
      const doc = yaml.load(readFileSync(resolve(REPO_ROOT, target), 'utf8'))
      for (const [jobName, job] of Object.entries(doc?.jobs ?? {})) {
        for (const step of job?.steps ?? []) {
          if (typeof step?.uses === 'string') {
            expect(
              step.uses,
              `${target} job "${jobName}" must not use actions/cache`,
            ).not.toMatch(/^actions\/cache(\/(restore|save))?@/)
          }
        }
      }
    }
  })
})
