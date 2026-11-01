import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  coreGoTests,
  goSelection as selectGoTests,
} from '../stack-conformance-selection.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

const readRepo = (path) => readFileSync(join(REPO_ROOT, path), 'utf8')
const conformanceScript = () =>
  readRepo('scripts/stack-conformance.sh').replace(/^\s*#.*$/gm, '')

function goSelection(script) {
  expect(script).toContain(
    'go_tests=$(node scripts/stack-conformance-selection.mjs)',
  )
  expect(script).toContain('go test -count=1 -v -run "$go_tests" ./encrypt')
  const result = spawnSync(
    process.execPath,
    ['scripts/stack-conformance-selection.mjs'],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    },
  )
  expect(result.status, result.stderr).toBe(0)
  return new RegExp(result.stdout.trim())
}

describe('shared Stack Encrypt conformance is required in CI', () => {
  it('the conformance task runs all profiles in both languages', () => {
    const script = readFileSync(
      join(REPO_ROOT, 'scripts/stack-conformance.sh'),
      'utf8',
    ).replace(/^\s*#.*$/gm, '')
    const commands = script.replace(/\\\r?\n\s*/g, ' ')
    expect(commands).toMatch(
      /STACK_CONFORMANCE_OUTPUT=[^\n]+go test[^\n]+"\$go_tests"/,
    )
    expect(commands).toMatch(
      /STACK_CONFORMANCE_INPUT=[^\n]+cargo nextest run[^\n]+--test conformance/,
    )
    expect(script).toMatch(/cargo nextest run[^\n]*--test conformance/)
    expect(script).toMatch(/cargo nextest run[^\n]*--test declarations/)
    expect(script).toMatch(/cargo nextest run[^\n]*--test runtime_conformance/)
    expect(script).toMatch(/cargo nextest run[^\n]*--test read_conformance/)
    expect(script).toMatch(/cargo nextest run[^\n]*--test context_conformance/)
    expect(script).toMatch(/cargo nextest run[^\n]*--test plan_grammar/)
    expect(script).toMatch(/cargo nextest run[^\n]*--test fixture_safety/)
    const selected = goSelection(script)
    for (const test of coreGoTests) {
      expect(selected.test(test), test).toBe(true)
    }
  })

  it('selects exactly the core runners and indexed fixture tests', () => {
    const index = JSON.parse(
      readRepo('conformance/stack-encrypt/v1/fixture-profiles.json'),
    )
    const expected = [
      ...new Set([
        ...coreGoTests,
        ...index.profiles.flatMap((p) =>
          p.requirements.flatMap((r) => r.go_tests),
        ),
      ]),
    ].sort()
    const selected = goSelection(conformanceScript())
    expect(selected.source).toBe(`^(${expected.join('|')})$`)
    for (const name of expected) {
      expect(selected.test(`${name}Extra`)).toBe(false)
      expect(selected.test(`Prefix${name}`)).toBe(false)
    }
    const extended = structuredClone(index)
    extended.profiles[0].requirements[0].go_tests.push(
      'TestNewFixtureRequirement',
    )
    expect(
      new RegExp(selectGoTests(extended)).test('TestNewFixtureRequirement'),
    ).toBe(true)
    extended.profiles[0].requirements[0].go_tests.push('Test.*')
    expect(() => selectGoTests(extended)).toThrow('Invalid Go test name')
  })

  it('enrolls existing fixture evidence without copying or dropping tests', () => {
    const index = JSON.parse(
      readRepo('conformance/stack-encrypt/v1/fixture-profiles.json'),
    )
    expect(Object.keys(index).sort()).toEqual(['profiles', 'version'])
    expect(index.version).toBe(1)
    expect(index.profiles.map((profile) => profile.id).sort()).toEqual([
      'record-context-fields-v1',
      'record-query-operators-v1',
      'record-value-kinds-v1',
    ])
    const script = conformanceScript()
    const selected = goSelection(script)
    const contract = readRepo('conformance/stack-encrypt/fixture-contract.md')
    const requirements = new Set()
    for (const profile of index.profiles) {
      expect(Object.keys(profile).sort()).toEqual([
        'fixture',
        'go_source',
        'id',
        'requirements',
        'rust_binary',
      ])
      expect(profile.rust_binary).toMatch(/^[a-z_]+$/)
      expect(profile.fixture).toBe(
        `packages/stack-encrypt/tests/fixtures/${profile.rust_binary}.json`,
      )
      expect(JSON.parse(readRepo(profile.fixture))).toHaveProperty('plan')
      expect(profile.go_source).toMatch(
        /^languages\/golang\/encrypt\/\w+_test\.go$/,
      )
      const rust = readRepo(
        `packages/stack-encrypt/tests/${profile.rust_binary}.rs`,
      )
      const go = readRepo(profile.go_source)
      expect(rust).toContain(`${profile.rust_binary}.json`)
      expect(go).toContain(`${profile.rust_binary}.json`)
      expect(script).toMatch(
        new RegExp(
          `cargo nextest run[^\\n]*--test ${profile.rust_binary}(?: |$)`,
          'm',
        ),
      )
      expect(profile.requirements.length).toBeGreaterThan(0)
      expect(contract).toContain(profile.id)
      for (const requirement of profile.requirements) {
        expect(Object.keys(requirement).sort()).toEqual([
          'go_tests',
          'id',
          'rust_tests',
        ])
        expect(requirement.id).toMatch(/^(values|queries|contexts)\.[a-z-]+$/)
        expect(requirements.has(requirement.id), requirement.id).toBe(false)
        requirements.add(requirement.id)
        expect(contract).toContain(`\`${requirement.id}\``)
        expect(requirement.rust_tests.length).toBeGreaterThan(0)
        expect(requirement.go_tests.length).toBeGreaterThan(0)
        for (const test of requirement.rust_tests) {
          expect(test).toMatch(/^[a-z_]+$/)
          expect(rust).toMatch(
            new RegExp(`#\\[(?:tokio::)?test\\]\\s+(?:async )?fn ${test}\\(`),
          )
        }
        for (const test of requirement.go_tests) {
          expect(test).toMatch(/^Test\w+$/)
          expect(go).toContain(`func ${test}(t *testing.T)`)
          expect(selected.test(test), `${requirement.id}: ${test}`).toBe(true)
        }
      }
    }
    const documented = [
      ...contract.matchAll(/\| `((?:values|queries|contexts)\.[a-z-]+)` \|/g),
    ].map((match) => match[1])
    expect([...requirements].sort()).toEqual(documented.sort())
  })

  it.each(['STACK_CONFORMANCE_UPDATE', 'STACK_ENCRYPT_UPDATE_FIXTURES'])(
    'refuses %s before invoking either language or modifying fixtures',
    (variable) => {
      // Empty is still set: Rust's fixture writers use var_os().is_some().
      const result = spawnSync('bash', ['scripts/stack-conformance.sh'], {
        cwd: REPO_ROOT,
        env: { ...process.env, [variable]: '' },
        encoding: 'utf8',
      })
      expect(result.status).toBe(1)
      expect(result.stderr).toContain(
        'Conformance checks must not update frozen artifacts.',
      )
      expect(result.stdout).toBe('')
    },
  )

  it('runs both consumers when the corpus changes', () => {
    for (const file of ['tests-crates.yml', 'tests-golang.yml']) {
      const workflow = readWorkflow(`.github/workflows/${file}`)
      const triggers = workflow.on ?? workflow[true]
      for (const event of ['pull_request', 'push']) {
        expect(triggers[event].paths).toContain('conformance/stack-encrypt/**')
        expect(triggers[event].paths).toContain('packages/stack-encrypt/**')
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
      (step) => step.env?.STACK_CONFORMANCE_INPUT,
    )
    expect(build).toBeGreaterThanOrEqual(0)
    const producer = steps.findIndex(
      (step) => step.env?.STACK_CONFORMANCE_OUTPUT,
    )
    expect(producer).toBeGreaterThan(build)
    expect(steps[producer].run).toContain('mise run go:test')
    expect(steps[producer].env.STACK_CONFORMANCE_OUTPUT).toBe(
      steps[exchange].env.STACK_CONFORMANCE_INPUT,
    )
    expect(steps[exchange].run).toContain('test -s "$STACK_CONFORMANCE_INPUT"')
    expect(steps[exchange].run).toMatch(
      /cargo nextest run[^\n]*--test conformance/,
    )
    expect(steps[exchange].run).not.toContain('test:conformance')
    expect(exchange).toBeGreaterThan(producer)
    const goTests = readFileSync(
      join(REPO_ROOT, 'scripts/go-binding-test.sh'),
      'utf8',
    )
    expect(goTests).toContain('set -- -count=1')
    expect(goTests).toContain('go test "$@" ./...')
    expect(steps[exchange].if).toBeUndefined()
    expect(steps[exchange]['continue-on-error']).toBeUndefined()
  })
})
