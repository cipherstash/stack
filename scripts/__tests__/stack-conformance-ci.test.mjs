import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

describe('shared Stack Encrypt conformance is required in CI', () => {
  it('the conformance task runs both profiles in both languages', () => {
    const script = readFileSync(
      join(REPO_ROOT, 'scripts/stack-conformance.sh'),
      'utf8',
    ).replace(/^\s*#.*$/gm, '')
    expect(script).toMatch(/cargo nextest run[^\n]*--test conformance/)
    expect(script).toMatch(/cargo nextest run[^\n]*--test declarations/)
    expect(script).toContain(
      "go test -count=1 -v -run '^(TestStackConformance|TestDeclarationConformance)$' ./encrypt",
    )
  })

  it('runs both consumers when the corpus changes', () => {
    for (const file of ['tests-crates.yml', 'tests-golang.yml']) {
      const workflow = readWorkflow(`.github/workflows/${file}`)
      const triggers = workflow.on ?? workflow[true]
      for (const event of ['pull_request', 'push']) {
        expect(triggers[event].paths).toContain('conformance/stack-encrypt/**')
      }
    }
  })

  it('requires the Go guest and runs fresh exchange after building it', () => {
    const workflow = readWorkflow('.github/workflows/tests-golang.yml')
    expect(workflow.env.STACK_CONFORMANCE_REQUIRED).toBe('1')
    const triggers = workflow.on ?? workflow[true]
    for (const event of ['pull_request', 'push']) {
      expect(triggers[event].paths).toContain('scripts/stack-conformance.sh')
    }
    const steps = workflow.jobs['wasi-check'].steps
    const build = steps.findIndex(
      (step) => step.run === 'mise run wasm:guest:build:deterministic',
    )
    const exchange = steps.findIndex(
      (step) => step.run === 'mise run test:conformance',
    )
    expect(build).toBeGreaterThanOrEqual(0)
    expect(exchange).toBeGreaterThan(build)
    expect(steps[exchange].if).toBeUndefined()
    expect(steps[exchange]['continue-on-error']).toBeUndefined()
  })
})
