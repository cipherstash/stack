import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  checkEnvironment,
  checkGoResults,
  checkRustInventory,
  selections,
} from '../stack-eql-conformance.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const read = (path) => readFileSync(join(REPO_ROOT, path), 'utf8')
const index = JSON.parse(
  read('conformance/stack-encrypt/v1/eql-json-profiles.json'),
)

describe('required EQL/JSON conformance', () => {
  it('enrolls every operation family and both language/database lanes', () => {
    expect(index.requirements.map((r) => r.id)).toEqual([
      'eql-resolver-catalog-v1',
      'json-write-v1',
      'json-query-v1',
      'json-request-bound-reads-v1',
      'json-element-match-v1',
      'json-predicate-match-v1',
      'json-extraction-v1',
      'json-subtree-v1',
      'json-tamper-v1',
    ])
    const contract = read('conformance/stack-encrypt/eql-json-contract.md')
    for (const requirement of index.requirements)
      expect(contract).toContain(requirement.id)
    const reached = new Set()
    for (const lane of ['fast', 'postgres']) {
      for (const language of ['rust', 'go']) {
        for (const [id, suite] of selections(index, lane, language)) {
          reached.add(id)
          expect(suite.tests.size).toBeGreaterThan(0)
        }
      }
    }
    expect([...reached].sort()).toEqual(Object.keys(index.suites).sort())
    const renamed = structuredClone(index)
    renamed.requirements[0].evidence.missing = ['TestMissing']
    expect(() => selections(renamed, 'fast', 'all')).toThrow('Invalid suite')
    expect(() => selections(index, 'unknown', 'all')).toThrow()
  })

  it('refuses renamed, filtered or wrongly ignored compiled native evidence', () => {
    const suite = {
      package: 'engine',
      binary: 'json',
      lane: 'fast',
      tests: new Set(['required']),
    }
    const inventory = {
      'rust-suites': {
        'engine::json': {
          status: 'listed',
          testcases: {
            required: { ignored: false, 'filter-match': { status: 'matches' } },
          },
        },
      },
    }
    expect(() => checkRustInventory(inventory, suite)).not.toThrow()
    for (const replacement of [
      undefined,
      { ignored: true, 'filter-match': { status: 'matches' } },
      { ignored: false, 'filter-match': { status: 'mismatch' } },
    ]) {
      const changed = structuredClone(inventory)
      changed['rust-suites']['engine::json'].testcases.required = replacement
      expect(() => checkRustInventory(changed, suite)).toThrow(
        'Missing or incorrectly ignored',
      )
    }
    expect(() =>
      checkRustInventory(inventory, { ...suite, lane: 'postgres' }),
    ).toThrow()
    inventory['rust-suites']['engine::json'].testcases.required.ignored = true
    expect(() =>
      checkRustInventory(inventory, { ...suite, lane: 'postgres' }),
    ).not.toThrow()
  })

  it('requires a Go pass for every name and rejects nested skips', () => {
    const passed = JSON.stringify({ Action: 'pass', Test: 'TestRequired' })
    expect(() => checkGoResults(passed, ['TestRequired'])).not.toThrow()
    expect(() => checkGoResults('', ['TestRequired'])).toThrow('did not pass')
    for (const action of ['skip', 'fail']) {
      const output = `${passed}\n${JSON.stringify({ Action: action, Test: 'TestRequired/case' })}`
      expect(() => checkGoResults(output, ['TestRequired'])).toThrow(action)
    }
    expect(() => checkGoResults(passed, ['TestRenamed'])).toThrow(
      'did not pass',
    )
  })

  it('refuses every update-variable spelling, including an empty or zero value', () => {
    for (const name of [
      'STACK_CONFORMANCE_UPDATE',
      'STACK_ENCRYPT_UPDATE_FIXTURES',
      'STACK_ENCRYPT_UPDATE_JSON_TREE_VECTORS',
    ]) {
      for (const value of ['', '0', '1'])
        expect(() => checkEnvironment({ [name]: value })).toThrow(name)
    }
    expect(() => checkEnvironment({})).not.toThrow()
  })

  it('shares the original write and predicate tables without dropping boundary cases', () => {
    const corpus = JSON.parse(
      read('conformance/stack-encrypt/v1/eql-json.json'),
    )
    expect(corpus.version).toBe(1)
    expect(new Set(corpus.documents).size).toBe(corpus.documents.length)
    for (const text of [
      'null',
      '{}',
      '[]',
      '18446744073709551615',
      '-9223372036854775808',
      '-926809.5051008083',
    ])
      expect(corpus.documents).toContain(text)
    expect(corpus.invalid_documents.map((c) => c.reason)).toEqual([
      'json_duplicate_key',
      'json_integer_range',
      'json_syntax',
      'json_syntax',
    ])
    expect(
      corpus.predicate_refusals.find((c) => c.id === 'too-deep'),
    ).not.toHaveProperty('vars')
    const ids = corpus.predicate_refusals.map((c) => c.id)
    expect(new Set(ids).size).toBe(15)
    for (const c of corpus.predicate_refusals) {
      expect(c.at).toBeGreaterThanOrEqual(0)
      expect(c.at).toBeLessThan(Buffer.byteLength(c.predicate))
      expect(c.reason).toMatch(/^json_/)
      expect(c.construct).toBeTruthy()
      expect(Buffer.from(c.predicate).subarray(c.at).toString()).toBe(c.at_text)
    }
    for (const path of [
      'packages/stack-encrypt/tests/json_operators.rs',
      'packages/eql/tests/encryption/tests/json_tree_data_plan.rs',
      'languages/golang/encrypt/json_conformance_test.go',
    ])
      expect(read(path)).toContain('eql-json.json')
  })

  it('runs both required lanes in CI and retains reports with SQL and engine identity', () => {
    const workflow = readWorkflow('.github/workflows/tests-golang.yml')
    const eqlSetup = workflow.jobs['wasi-check'].steps.find(
      (step) =>
        step.uses?.startsWith('jdx/mise-action@') &&
        step.with?.working_directory === 'packages/eql',
    )
    // Installing the EQL tools must not export its local DATABASE_URL into
    // the hermetic Go job, which has no PostgreSQL service.
    expect(eqlSetup).toBeDefined()
    expect(eqlSetup.with.env).toBe(false)
    for (const task of ['test:conformance:eql', 'go:test:postgres']) {
      const jobs = Object.values(workflow.jobs).filter((job) =>
        job.steps?.some((step) => step.run === `mise run ${task}`),
      )
      expect(jobs).toHaveLength(1)
      const step = jobs[0].steps.find((step) => step.run === `mise run ${task}`)
      expect(step['continue-on-error']).toBeUndefined()
      expect(jobs[0].env.MISE_ENV).toBe('test')
      expect(step.env.STACK_CONFORMANCE_REPORT_DIR).toBeTruthy()
      if (task.endsWith(':postgres')) {
        const steps = jobs[0].steps
        const repair = steps.findIndex((s) =>
          s.run?.includes('mise install --force rust'),
        )
        const cache = steps.findIndex((s) =>
          s.uses?.startsWith('Swatinem/rust-cache@'),
        )
        expect(repair).toBeGreaterThan(-1)
        expect(cache).toBeGreaterThan(repair)
        expect(steps[repair].run).toContain(
          'mise -C packages/eql install --force rust',
        )
        expect(steps[repair].run).toContain('mise x -- cargo --version')
        expect(steps[repair].run).toContain(
          'mise -C packages/eql x -- cargo --version',
        )
        expect(jobs[0].services.postgres).toBeDefined()
        expect(step.env.EQL_TEST_DATABASE_URL).toContain(
          'job.services.postgres.ports',
        )
      }
      expect(
        jobs[0].steps.some(
          (s) =>
            s.uses?.startsWith('actions/upload-artifact@') &&
            s.with?.path?.includes('eql-conformance') &&
            s.with['if-no-files-found'] === 'error',
        ),
      ).toBe(true)
    }
    // Parse YAML paths rather than counting source spellings or indentation.
    for (const event of ['push', 'pull_request']) {
      expect(workflow.on[event].paths).toContain(
        'scripts/stack-eql-conformance.mjs',
      )
    }
    const tasks = read('mise.toml')
    const postgresTask = tasks
      .split('[tasks."go:test:postgres"]')[1]
      .split('[tasks.')[0]
    expect(postgresTask).toContain('mise run test:conformance:eql:postgres')
    expect(postgresTask).not.toMatch(/^psql\s/m)
    expect(postgresTask).not.toContain('mise -C packages/eql run build')
  })
})
