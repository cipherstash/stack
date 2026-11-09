#!/usr/bin/env node
// Named evidence over the existing suites. Missing, ignored and skipped tests
// are failures; a successful empty selection is not conformance.
import { fileURLToPath } from 'node:url'
import {
  cargo,
  checkEnvironment,
  command,
  hash,
  read,
  runSuite,
  selections,
  writeReport,
} from './stack-conformance-evidence.mjs'

export {
  checkEnvironment,
  checkGoResults,
  checkRustInventory,
  selections,
} from './stack-conformance-evidence.mjs'

function metadata(workspace) {
  return JSON.parse(
    cargo(
      [
        'metadata',
        '--locked',
        '--no-deps',
        '--format-version',
        '1',
        '--manifest-path',
        'Cargo.toml',
      ],
      true,
      workspace,
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
    read('conformance/stack-encrypt/v1/eql-json-v1.enrollment.json'),
  )
  if (index.profile !== 'eql-json-v1')
    throw new Error(`Unsupported EQL conformance profile: ${index.profile}`)
  const selected = selections(index, lane, language)
  process.env.STACK_CONFORMANCE_REQUIRED = '1'
  delete process.env.STACK_CONFORMANCE_INPUT
  delete process.env.STACK_CONFORMANCE_OUTPUT
  const report = {
    profile: 'eql-json-v1',
    lane,
    language,
    engine: metadata('.').packages.find((p) => p.name === 'stack-encrypt')
      .version,
    eql_bindings: metadata('packages/eql').packages.find(
      (p) => p.name === 'eql-bindings',
    ).version,
    corpus_sha256: hash('conformance/stack-encrypt/v1/eql-json-v1.cases.json'),
    enrollment_sha256: hash(
      'conformance/stack-encrypt/v1/eql-json-v1.enrollment.json',
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
    report.expected_schema = 'eql_v4'
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
          "select json_build_object('postgres', current_setting('server_version'), 'eql', eql_v4.version(), 'schema', (select nspname from pg_namespace where oid = to_regnamespace('eql_v4')))",
        ],
        { capture: true },
      ),
    )
    process.env.DATABASE_URL = url
  }
  for (const [id, suite] of selected) {
    console.log(`EQL conformance: ${id} (${suite.tests.size} required tests)`)
    runSuite(suite, { wholeBinary: true })
    report.evidence[id] = [...suite.tests].sort()
  }
  writeReport(`eql-json-${lane}-${language}.json`, report)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
