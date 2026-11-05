// Execution and non-vacuity checks shared by conformance profiles.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const read = (path) => readFileSync(join(root, path), 'utf8')
export const hash = (path) =>
  createHash('sha256')
    .update(readFileSync(join(root, path)))
    .digest('hex')

export function selections(index, lane, language) {
  if (
    index.version !== 1 ||
    !['fast', 'postgres'].includes(lane) ||
    !['rust', 'go', 'all'].includes(language)
  ) {
    throw new Error('Unsupported conformance version, lane or language')
  }
  const selected = new Map()
  const ids = new Set()
  for (const requirement of index.requirements) {
    if (!/^[a-z][a-z0-9-]+-v1$/.test(requirement.id) || ids.has(requirement.id))
      throw new Error('Invalid or repeated requirement ID')
    ids.add(requirement.id)
    if (!Object.keys(requirement.evidence).length)
      throw new Error(`Empty evidence: ${requirement.id}`)
    for (const [id, tests] of Object.entries(requirement.evidence)) {
      const suite = index.suites[id]
      if (
        !suite ||
        !['rust', 'go'].includes(suite.language) ||
        !['fast', 'postgres'].includes(suite.lane)
      )
        throw new Error(`Invalid suite: ${id}`)
      if (
        !tests.length ||
        new Set(tests).size !== tests.length ||
        tests.some(
          (name) =>
            !(suite.language === 'go' ? /^Test\w+$/ : /^[a-zA-Z0-9_:]+$/).test(
              name,
            ),
        )
      )
        throw new Error(`Invalid tests: ${id}`)
      if (
        suite.lane !== lane ||
        (language !== 'all' && language !== suite.language)
      )
        continue
      if (!selected.has(id)) selected.set(id, { ...suite, tests: new Set() })
      for (const name of tests) selected.get(id).tests.add(name)
    }
  }
  if (!selected.size) throw new Error('No EQL conformance evidence selected')
  return selected
}

export function checkRustInventory(inventory, suite) {
  const binary =
    inventory['rust-suites'][
      suite.lib ? suite.package : `${suite.package}::${suite.binary}`
    ]
  if (binary?.status !== 'listed')
    throw new Error(`Missing compiled binary: ${suite.binary}`)
  for (const name of suite.tests) {
    const test = binary.testcases[name]
    if (
      !test ||
      test.ignored !== (suite.lane === 'postgres') ||
      test['filter-match'].status !== 'matches'
    ) {
      throw new Error(
        `Missing or incorrectly ignored compiled test: ${suite.binary}::${name}`,
      )
    }
  }
}

export function checkGoResults(output, tests) {
  const passed = new Set()
  for (const line of output.trim().split('\n')) {
    if (!line) continue
    const event = JSON.parse(line)
    if (event.Action === 'skip' || event.Action === 'fail')
      throw new Error(
        `Go conformance ${event.Action}: ${event.Test ?? event.Package}`,
      )
    if (event.Action === 'pass' && event.Test) passed.add(event.Test)
  }
  for (const name of tests)
    if (!passed.has(name)) throw new Error(`Go test did not pass: ${name}`)
}

export function checkEnvironment(env) {
  for (const name of [
    'STACK_CONFORMANCE_UPDATE',
    'STACK_ENCRYPT_UPDATE_FIXTURES',
    'STACK_ENCRYPT_UPDATE_JSON_TREE_VECTORS',
  ]) {
    if (Object.hasOwn(env, name))
      throw new Error(`Conformance cannot update fixtures: ${name}`)
  }
}

export function command(program, args, { capture = false, ...options } = {}) {
  const result = spawnSync(program, args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit',
    ...options,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    if (capture && result.stdout) process.stderr.write(result.stdout)
    throw new Error(`${program} failed (${result.status})`)
  }
  return result.stdout
}

export function cargo(args, capture = false, workspace = '.') {
  return command('mise', ['x', '--env', 'test', '--', 'cargo', ...args], {
    capture,
    cwd: join(root, workspace),
  })
}

// The nextest arguments shared by `list` and `run`. A whole-binary suite (EQL)
// runs every test in its binary; otherwise only the enrolled tests run.
export function nextestArgs(suite, { wholeBinary = false } = {}) {
  const args = [
    '--locked',
    '--manifest-path',
    'Cargo.toml',
    '-p',
    suite.package,
    ...(suite.lib ? ['--lib'] : ['--test', suite.binary]),
    ...suite.features,
    '--run-ignored',
    suite.lane === 'postgres' ? 'only' : 'default',
  ]
  if (!wholeBinary)
    args.push(
      '-E',
      [...suite.tests].map((name) => `test(=${name})`).join(' | '),
    )
  return args
}

export function runSuite(suite, { wholeBinary = false } = {}) {
  const lane = suite.lane
  if (suite.language === 'rust') {
    const common = nextestArgs(suite, { wholeBinary })
    const inventory = JSON.parse(
      cargo(
        ['nextest', 'list', ...common, '--message-format', 'json'],
        true,
        suite.workspace,
      ),
    )
    checkRustInventory(inventory, suite)
    // EQL retains whole binaries. Lifecycle selects enrolled tests from large
    // unit suites. PostgreSQL tests are intentionally ignored in the fast lane.
    cargo(
      [
        'nextest',
        'run',
        ...common,
        '--success-output',
        suite.success_output ?? (lane === 'postgres' ? 'immediate' : 'never'),
      ],
      false,
      suite.workspace,
    )
  } else {
    const pattern = `^(${[...suite.tests].sort().join('|')})$`
    const output = command(
      'go',
      [
        'test',
        '-C',
        'languages/golang',
        '-count=1',
        '-json',
        '-run',
        pattern,
        suite.package ?? './encrypt',
      ],
      { capture: true, env: { ...process.env, CGO_ENABLED: '0' } },
    )
    checkGoResults(output, suite.tests)
    console.log(`Passed ${suite.tests.size} required Go tests; no skips`)
  }
}
