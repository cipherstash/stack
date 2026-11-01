#!/usr/bin/env node
// Named evidence over the existing suites. Missing, ignored and skipped tests
// are failures; a successful empty selection is not conformance.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const read = (path) => readFileSync(join(root, path), 'utf8')
const hash = (path) =>
  createHash('sha256')
    .update(readFileSync(join(root, path)))
    .digest('hex')

export function selections(index, lane, language) {
  if (
    index.version !== 1 ||
    !['fast', 'postgres'].includes(lane) ||
    !['rust', 'go', 'all'].includes(language)
  ) {
    throw new Error('Unsupported EQL conformance version, lane or language')
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
  const binary = inventory['rust-suites'][`${suite.package}::${suite.binary}`]
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

function command(program, args, { capture = false, ...options } = {}) {
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

function cargo(args, capture = false) {
  return command('mise', ['x', '--env', 'test', '--', 'cargo', ...args], {
    capture,
  })
}

function metadata(manifest) {
  return JSON.parse(
    cargo(
      [
        'metadata',
        '--locked',
        '--no-deps',
        '--format-version',
        '1',
        '--manifest-path',
        manifest,
      ],
      true,
    ),
  )
}

export function main(args = process.argv.slice(2)) {
  // Positional arguments intentionally have no implicit database fallback.
  const [lane, language = 'all'] = args
  if (args.length > 2)
    throw new Error(
      'Usage: stack-eql-conformance.mjs <fast|postgres> [rust|go|all]',
    )
  checkEnvironment(process.env)
  const index = JSON.parse(
    read('conformance/stack-encrypt/v1/eql-json-profiles.json'),
  )
  const selected = selections(index, lane, language)
  process.env.STACK_CONFORMANCE_REQUIRED = '1'
  delete process.env.STACK_CONFORMANCE_INPUT
  delete process.env.STACK_CONFORMANCE_OUTPUT
  const report = {
    profile: 'eql-json-v1',
    lane,
    language,
    engine: metadata('Cargo.toml').packages.find(
      (p) => p.name === 'stack-encrypt',
    ).version,
    eql_bindings: metadata('packages/eql/Cargo.toml').packages.find(
      (p) => p.name === 'eql-bindings',
    ).version,
    corpus_sha256: hash('conformance/stack-encrypt/v1/eql-json.json'),
    enrollment_sha256: hash(
      'conformance/stack-encrypt/v1/eql-json-profiles.json',
    ),
    root_lock_sha256: hash('Cargo.lock'),
    eql_lock_sha256: hash('packages/eql/Cargo.lock'),
    evidence: {},
  }
  if ([...selected.values()].some((s) => s.language === 'go')) {
    // Both builds are required: capability refusal is tested with the plain guest.
    report.guests = Object.fromEntries(
      [
        'stack_encrypt_guest_deterministic.wasm',
        'stack_encrypt_guest_eql_deterministic.wasm',
      ].map((name) => [
        name,
        hash(`languages/golang/encrypt/testdata/${name}`),
      ]),
    )
  }
  if (lane === 'postgres') {
    const url = process.env.EQL_TEST_DATABASE_URL
    if (!url)
      throw new Error(
        'Set EQL_TEST_DATABASE_URL to a disposable PostgreSQL database',
      )
    const bundle = 'packages/eql/release/cipherstash-encrypt-v4.sql'
    report.sql_bundle_sha256 = hash(bundle)
    // Install exactly the bytes whose identity is recorded, into the same
    // database both runners use. Never report a merely adjacent bundle's hash.
    command('psql', ['-X', url, '-v', 'ON_ERROR_STOP=1', '-q', '-f', bundle])
    report.database = JSON.parse(
      command(
        'psql',
        [
          '-X',
          url,
          '-At',
          '-v',
          'ON_ERROR_STOP=1',
          '-c',
          "select json_build_object('postgres', current_setting('server_version'), 'eql', eql_v4.version(), 'schema', 4)",
        ],
        { capture: true },
      ),
    )
    process.env.DATABASE_URL = url
  }
  for (const [id, suite] of selected) {
    console.log(`EQL conformance: ${id} (${suite.tests.size} required tests)`)
    if (suite.language === 'rust') {
      const common = [
        '--locked',
        '--manifest-path',
        `${suite.workspace}/Cargo.toml`,
        '-p',
        suite.package,
        '--test',
        suite.binary,
        ...suite.features,
        '--run-ignored',
        lane === 'postgres' ? 'only' : 'default',
      ]
      const inventory = JSON.parse(
        cargo(['nextest', 'list', ...common, '--message-format', 'json'], true),
      )
      checkRustInventory(inventory, suite)
      // Run the whole original suite, retaining unindexed regression and property
      // tests. PostgreSQL tests are intentionally #[ignore] outside this lane.
      cargo([
        'nextest',
        'run',
        ...common,
        '--success-output',
        lane === 'postgres' ? 'immediate' : 'never',
      ])
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
          './encrypt',
        ],
        { capture: true, env: { ...process.env, CGO_ENABLED: '0' } },
      )
      checkGoResults(output, suite.tests)
      console.log(`Passed ${suite.tests.size} required Go tests; no skips`)
    }
    report.evidence[id] = [...suite.tests].sort()
  }
  console.log(JSON.stringify(report, null, 2))
  if (process.env.STACK_CONFORMANCE_REPORT_DIR) {
    mkdirSync(process.env.STACK_CONFORMANCE_REPORT_DIR, { recursive: true })
    writeFileSync(
      join(
        process.env.STACK_CONFORMANCE_REPORT_DIR,
        `eql-json-${lane}-${language}.json`,
      ),
      `${JSON.stringify(report, null, 2)}\n`,
    )
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
