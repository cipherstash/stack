import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  checkRustInventory,
  selections,
} from '../stack-conformance-evidence.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const read = (path) => readFileSync(join(REPO_ROOT, path), 'utf8')
const index = JSON.parse(
  read('conformance/stack-encrypt/v1/lifecycle-profiles.json'),
)

describe('required lifecycle evidence', () => {
  it('enrolls each guarantee and keeps limitations outside passing evidence', () => {
    expect(index.requirements.map((r) => r.id)).toEqual([
      'lifecycle-ownership-v1',
      'lifecycle-cancellation-v1',
      'lifecycle-partial-output-v1',
      'lifecycle-buffer-cleanup-v1',
      'lifecycle-diagnostics-v1',
      'lifecycle-validation-before-io-v1',
      'lifecycle-logical-batching-v1',
      'lifecycle-provider-chunks-v1',
    ])
    const contract = read('conformance/stack-encrypt/lifecycle-contract.md')
    for (const r of index.requirements) expect(contract).toContain(r.id)
    const selected = selections(index, 'fast', 'all')
    expect([...selected.keys()].sort()).toEqual(
      Object.keys(index.suites).sort(),
    )
    expect(
      selected
        .get('go')
        .tests.has('TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt'),
    ).toBe(false)
    expect(index.limitations).toContainEqual(
      expect.objectContaining({
        id: 'go-post-decrypt-shadow-stack',
        status: 'known-gap',
      }),
    )
    expect(index.limitations).toContainEqual(
      expect.objectContaining({
        id: 'python-typescript-lifecycle',
        status: 'not-enrolled',
      }),
    )
    for (const limitation of index.limitations)
      expect(contract).toContain(limitation.id)
  })

  it('checks compiled library names as strictly as integration binaries', () => {
    const suite = {
      package: 'engine',
      lib: true,
      lane: 'fast',
      tests: new Set(['nested::required']),
    }
    const inventory = {
      'rust-suites': {
        engine: {
          status: 'listed',
          testcases: {
            'nested::required': {
              ignored: false,
              'filter-match': { status: 'matches' },
            },
          },
        },
      },
    }
    expect(() => checkRustInventory(inventory, suite)).not.toThrow()
    delete inventory['rust-suites'].engine.testcases['nested::required']
    expect(() => checkRustInventory(inventory, suite)).toThrow(
      'Missing or incorrectly ignored',
    )
  })

  it('preserves package boundaries and fails on a missing requirement', () => {
    const selected = selections(index, 'fast', 'go')
    expect([...selected.values()].map((s) => s.package).sort()).toEqual([
      './encrypt',
      './encrypt/gensupport',
      './internal/guest',
    ])
    const changed = structuredClone(index)
    changed.requirements[0].evidence.go = []
    expect(() => selections(changed, 'fast', 'go')).toThrow('Invalid tests')
  })

  it('runs the lifecycle task in required CI and retains its report', () => {
    const workflow = readWorkflow('.github/workflows/tests-golang.yml')
    const job = workflow.jobs['wasi-check']
    expect(job.env.MISE_ENV).toBe('test')
    const step = job.steps.find(
      (s) => s.run === 'mise run test:conformance:lifecycle',
    )
    expect(step).toBeDefined()
    expect(step.if).toBeUndefined()
    expect(step['continue-on-error']).toBeUndefined()
    expect(step.env.STACK_CONFORMANCE_REPORT_DIR).toBeTruthy()
    expect(
      job.steps.some(
        (s) =>
          s.uses?.startsWith('actions/upload-artifact@') &&
          s.with?.name === 'lifecycle-conformance' &&
          s.with['if-no-files-found'] === 'error',
      ),
    ).toBe(true)
    for (const event of ['push', 'pull_request']) {
      for (const path of [
        'scripts/stack-conformance-evidence.mjs',
        'scripts/stack-lifecycle-conformance.mjs',
        'conformance/stack-encrypt/**',
      ])
        expect(workflow.on[event].paths).toContain(path)
    }
  })
})
