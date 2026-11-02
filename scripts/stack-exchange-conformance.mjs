#!/usr/bin/env node
// Fresh cross-language artifact exchange: each enrolled runner writes
// artifacts in a fresh directory and the other opens them. Producer caches
// are bypassed (nextest reruns; `go test -count=1`), a missing runner or
// guest fails before anything runs, an empty fresh output fails, and the
// report records who produced what with which engine, backend and storage
// versions. See conformance/stack-encrypt/exchange-contract.md.
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  cargo,
  checkEnvironment,
  command,
  hash,
  read,
  root,
  runSuite,
  writeReport,
} from './stack-conformance-evidence.mjs'

export const PROFILE = 'artifact-exchange-v1'
export const CORPUS = 'conformance/stack-encrypt/v1/exchange.json'

/** The guests the Go runner needs, relative to the Go module. */
export const GUESTS = [
  'encrypt/testdata/stack_encrypt_guest_deterministic.wasm',
  'encrypt/testdata/stack_encrypt_guest_eql_deterministic.wasm',
]

/** The language runners this profile enrolls today. */
export const RUNNERS = ['rust', 'go']

/** Languages whose runners do not exist yet: a gap, never a pass. */
export const NOT_ENROLLED = ['python', 'typescript']

/**
 * A required lane fails on a guest that is absent or empty rather than
 * skipping the tests that need it. `base` is the Go module directory.
 */
export function requireGuests(base, guests = GUESTS) {
  for (const guest of guests) {
    const path = join(base, guest)
    if (!existsSync(path) || statSync(path).size === 0)
      throw new Error(
        `Missing or empty guest: ${guest} (build it with mise run wasm:guest:build:deterministic and wasm:guest:build:eql:deterministic)`,
      )
  }
}

/**
 * A required lane fails on a runner that cannot be found rather than
 * leaving its half of the exchange unrun.
 */
export function requireRunner(program, args = ['version'], env = process.env) {
  const result = spawnSync(program, args, { encoding: 'utf8', env })
  if (result.error || result.status !== 0)
    throw new Error(
      `Missing runner: ${program} (${result.error?.code ?? `exit ${result.status}`})`,
    )
  return result.stdout.trim()
}

/** The lanes this profile runs, as (kind, producer, consumer) rows. */
export function lanes() {
  const rows = []
  for (const kind of ['values', 'record', 'blobs', 'eql-rows']) {
    rows.push({ kind, producer: 'go', consumer: 'rust' })
    rows.push({ kind, producer: 'rust', consumer: 'go' })
  }
  return rows
}

/**
 * The corpus's own shape: every lane this script runs is named by it, so
 * a corpus that drops one cannot leave the lane silently unrun.
 */
export function checkCorpus(corpus) {
  if (corpus.version !== 1 || corpus.profile !== PROFILE)
    throw new Error('Unsupported exchange corpus')
  if (
    corpus.values?.corpus !== 'values.json' ||
    corpus.values?.profile !== 'record-values-v1'
  )
    throw new Error('The exchange reads the value-boundary corpus')
  if (!corpus.record?.rows?.length || !corpus.record.fields?.length)
    throw new Error('The exchange record has fields and rows')
  if (!corpus.record.fields.some((field) => field.passthrough))
    throw new Error('The exchange record has a passthrough field')
  if (!corpus.blob?.cases?.length) throw new Error('The exchange has blobs')
  if (corpus.eql?.table !== 'profiles' || corpus.eql?.schema !== 'eql_v4')
    throw new Error('The exchange names the EQL lane')
  if (!existsSync(join(root, corpus.eql.fixture)))
    throw new Error(`Missing EQL fixture: ${corpus.eql.fixture}`)
}

/**
 * A fresh artifact file: present, nonempty, of this profile, written by
 * `language`, with every artifact set nonempty. The runners compare the
 * contents; this is what makes an empty or missing output a failure
 * rather than a vacuous pass.
 */
export function checkArtifacts(path, language, corpus) {
  if (!existsSync(path) || statSync(path).size === 0)
    throw new Error(`Empty fresh output: ${path}`)
  const artifacts = JSON.parse(readFileSync(path, 'utf8'))
  if (artifacts.version !== 1 || artifacts.profile !== PROFILE)
    throw new Error(`${path}: not ${PROFILE} version 1`)
  if (artifacts.producer?.language !== language)
    throw new Error(
      `${path}: produced by ${artifacts.producer?.language}, expected ${language}`,
    )
  for (const field of ['sdk', 'sdk_version', 'backend'])
    if (!artifacts.producer[field]) throw new Error(`${path}: no ${field}`)
  if (
    artifacts.producer.engine?.name !== 'stack-encrypt' ||
    !(
      artifacts.producer.engine.version ||
      artifacts.producer.engine.guest_sha256
    )
  )
    throw new Error(`${path}: the engine is not identified`)
  if (artifacts.producer.key_source?.seed !== corpus.seed)
    throw new Error(`${path}: not the corpus seed`)
  const counts = {}
  for (const kind of ['values', 'record', 'blobs']) {
    const ids = Object.keys(artifacts[kind] ?? {})
    if (!ids.length) throw new Error(`${path}: no ${kind} artifacts`)
    counts[kind] = ids.length
  }
  if (counts.record !== corpus.record.rows.length)
    throw new Error(`${path}: ${counts.record} record artifacts`)
  if (counts.blobs !== corpus.blob.cases.length)
    throw new Error(`${path}: ${counts.blobs} blob artifacts`)
  return { producer: artifacts.producer, counts }
}

/**
 * A fresh EQL rows file: present, nonempty, the fixture's table and
 * schema, rows, and a producer manifest naming `language`, its SDK and
 * the engine it ran.
 */
export function checkRows(path, language, corpus) {
  if (!existsSync(path) || statSync(path).size === 0)
    throw new Error(`Empty fresh output: ${path}`)
  const rows = JSON.parse(readFileSync(path, 'utf8'))
  if (rows.table !== corpus.eql.table || !rows.rows?.length)
    throw new Error(`${path}: not ${corpus.eql.table} rows`)
  const producer = rows.producer
  if (producer?.language !== language)
    throw new Error(
      `${path}: produced by ${producer?.language}, expected ${language}`,
    )
  for (const field of ['sdk', 'sdk_version', 'backend'])
    if (!producer[field]) throw new Error(`${path}: no ${field}`)
  if (
    producer.engine?.name !== 'stack-encrypt' ||
    !(producer.engine.version || producer.engine.guest_sha256)
  )
    throw new Error(`${path}: the engine is not identified`)
  if (producer.schema !== corpus.eql.schema)
    throw new Error(`${path}: not ${corpus.eql.schema} rows`)
  return { rows: rows.rows.length, producer }
}

/** `[[package]]` versions from a Cargo lockfile, for the named crates. */
export function lockedVersions(lock, names) {
  const versions = {}
  for (const match of lock.matchAll(
    /\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/g,
  )) {
    if (!names.includes(match[1])) continue
    versions[match[1]] = [...(versions[match[1]] ?? []), match[2]].sort()
  }
  for (const name of names)
    if (!versions[name]) throw new Error(`${name} is not in the lockfile`)
  return versions
}

const rustSuite = (binary, tests, workspace = '.', pkg = 'stack-encrypt') => ({
  language: 'rust',
  lane: 'fast',
  workspace,
  package: pkg,
  binary,
  features: workspace === '.' ? ['--all-features'] : [],
  tests: new Set(tests),
})
const goSuite = (tests) => ({
  language: 'go',
  lane: 'fast',
  tests: new Set(tests),
})

/** Run `suite` with `vars` set and every other exchange variable unset. */
function exchange(suite, vars) {
  for (const name of EXCHANGE_VARIABLES) delete process.env[name]
  Object.assign(process.env, vars)
  try {
    runSuite(suite)
  } finally {
    for (const name of EXCHANGE_VARIABLES) delete process.env[name]
  }
}

const EXCHANGE_VARIABLES = [
  'STACK_EXCHANGE_OUTPUT',
  'STACK_EXCHANGE_INPUT',
  'STACK_CONFORMANCE_OUTPUT',
  'STACK_CONFORMANCE_INPUT',
  'EQL_V4_ROWS_OUT',
  'EQL_V4_ROWS',
  'EQL_V4_RUST_ROWS_OUT',
  'EQL_V4_RUST_ROWS',
  'EQL_V4_SMALLINT_ROWS_OUT',
  'EQL_V4_SMALLINT_ROWS',
]

const ENGINE_CRATES = ['stack-encrypt', 'vitaminc-aead', 'vitaminc-aead-frame']

/**
 * What each lane's consumer compares. Never ciphertext bytes. Both EQL
 * consumers open every column through the typed targets and derive each
 * equality column's query term to compare with the stored `hm`.
 */
export function compared({ kind }) {
  if (kind === 'blobs') return 'decoded blob values'
  if (kind === 'eql-rows')
    return "decrypted columns; stored equality terms against the consumer's derived query terms"
  return "decrypted values; stored index terms against the consumer's derived query terms"
}

export function main(args = process.argv.slice(2)) {
  if (args.length)
    throw new Error('Usage: stack-exchange-conformance.mjs (no arguments)')
  checkEnvironment(process.env)
  const corpus = JSON.parse(read(CORPUS))
  checkCorpus(corpus)
  const goModule = join(root, 'languages/golang')
  // Fail here, by name, rather than part way through with one half run.
  requireGuests(goModule)
  const toolchains = {
    go: requireRunner('go'),
    rustc: requireRunner('mise', [
      'x',
      '--env',
      'test',
      '--',
      'rustc',
      '--version',
    ]),
  }
  process.env.STACK_CONFORMANCE_REQUIRED = '1'
  for (const name of EXCHANGE_VARIABLES) delete process.env[name]

  // Fresh every run: nothing here is read from or written to the tree.
  const fresh = mkdtempSync(join(tmpdir(), 'stack-exchange-'))
  const paths = {
    rust: join(fresh, 'rust.json'),
    go: join(fresh, 'go.json'),
    eqlGo: join(fresh, 'eql-go-rows.json'),
    eqlRust: join(fresh, 'eql-rust-rows.json'),
  }
  const stackRust = rustSuite('exchange_conformance', [
    'fresh_artifact_exchange',
  ])
  const stackGo = goSuite(['TestArtifactExchange'])
  const eqlRustProducer = rustSuite(
    'v4_types',
    ['rows_rust_seals_open_in_the_go_sdk'],
    'packages/eql',
    'eql-encryption-tests',
  )
  const eqlRustConsumer = rustSuite(
    'v4_types',
    ['rows_the_go_sdk_sealed_open_in_rust'],
    'packages/eql',
    'eql-encryption-tests',
  )
  const eqlGoProducer = goSuite(['TestV4RowsMatchTheCommittedFixture'])
  const eqlGoConsumer = goSuite(['TestV4RowsTheRustSuiteSealedOpenInGo'])

  let produced
  try {
    console.log('Exchange conformance: producing fresh artifacts')
    exchange(stackRust, { STACK_EXCHANGE_OUTPUT: paths.rust })
    exchange(stackGo, { STACK_EXCHANGE_OUTPUT: paths.go })
    exchange(eqlRustProducer, { EQL_V4_RUST_ROWS_OUT: paths.eqlRust })
    exchange(eqlGoProducer, { EQL_V4_ROWS_OUT: paths.eqlGo })
    produced = {
      rust: checkArtifacts(paths.rust, 'rust', corpus),
      go: checkArtifacts(paths.go, 'go', corpus),
      eqlRust: checkRows(paths.eqlRust, 'rust', corpus),
      eqlGo: checkRows(paths.eqlGo, 'go', corpus),
    }

    console.log(
      "Exchange conformance: opening each runner's artifacts in the other",
    )
    exchange(stackRust, { STACK_EXCHANGE_INPUT: paths.go })
    exchange(stackGo, { STACK_EXCHANGE_INPUT: paths.rust })
    exchange(eqlRustConsumer, { EQL_V4_ROWS: paths.eqlGo })
    exchange(eqlGoConsumer, { EQL_V4_RUST_ROWS: paths.eqlRust })
  } catch (error) {
    // Kept for inspection: the artifacts the failing lane read or wrote.
    console.error(`Exchange conformance: artifacts kept in ${fresh}`)
    throw error
  }
  rmSync(fresh, { recursive: true, force: true })

  const rootLock = read('Cargo.lock')
  const guestLock = read('languages/golang/encrypt/guest/Cargo.lock')
  const eqlLock = read('packages/eql/Cargo.lock')
  const metadata = JSON.parse(
    cargo(['metadata', '--locked', '--no-deps', '--format-version', '1'], true),
  )
  const eqlPackage = JSON.parse(read('packages/eql/packages/eql/package.json'))
  const report = {
    profile: PROFILE,
    corpus_sha256: hash(CORPUS),
    values_corpus_sha256: hash('conformance/stack-encrypt/v1/values.json'),
    eql_fixture_sha256: hash(corpus.eql.fixture),
    commit: command('git', ['rev-parse', 'HEAD'], { capture: true }).trim(),
    toolchains,
    engine: {
      stack_encrypt: metadata.packages.find((p) => p.name === 'stack-encrypt')
        .version,
      native: lockedVersions(rootLock, ENGINE_CRATES),
      guest: lockedVersions(guestLock, ENGINE_CRATES),
      eql_workspace: lockedVersions(eqlLock, [
        ...ENGINE_CRATES,
        'eql-bindings',
      ]),
    },
    storage: {
      eql_schema: corpus.eql.schema,
      eql_package: eqlPackage.version,
      eql_bindings: lockedVersions(eqlLock, ['eql-bindings'])['eql-bindings'],
      sql_lane:
        'The PostgreSQL oracle lane is tests-golang.yml eql-postgres (go:test:postgres), whose report records the installed bundle; this report records the versions the exchanged rows were derived under.',
    },
    locks: {
      root_sha256: hash('Cargo.lock'),
      guest_sha256: hash('languages/golang/encrypt/guest/Cargo.lock'),
      eql_sha256: hash('packages/eql/Cargo.lock'),
    },
    guests: Object.fromEntries(
      GUESTS.map((guest) => [guest, hash(`languages/golang/${guest}`)]),
    ),
    producers: {
      rust: produced.rust.producer,
      go: produced.go.producer,
      'eql-rows-rust': produced.eqlRust.producer,
      'eql-rows-go': produced.eqlGo.producer,
    },
    exchanged: lanes().map((lane) => ({
      ...lane,
      artifacts:
        lane.kind === 'eql-rows'
          ? produced[lane.producer === 'rust' ? 'eqlRust' : 'eqlGo'].rows
          : produced[lane.producer].counts[lane.kind],
      compared: compared(lane),
    })),
    not_enrolled: NOT_ENROLLED.map((language) => ({
      language,
      status: 'no runner',
    })),
    released_versions: {
      status: 'not defined',
      note: 'Only this checkout exchanged with itself. Supported released-version combinations follow the EQL v4 and Stack Encrypt compatibility policy, which is not written yet; rows are added when it is.',
      row_shape: {
        producer: { sdk: '<name>', version: '<release>' },
        consumer: { sdk: '<name>', version: '<release>' },
        storage: { eql_bundle: '<release>', schema: 'eql_v4' },
        kinds: ['values', 'record', 'blobs', 'eql-rows'],
        result: 'opens | refused (<documented reason>)',
      },
      rows: [],
    },
  }
  writeReport('exchange.json', report)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
