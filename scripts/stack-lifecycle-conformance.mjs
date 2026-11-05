#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  cargo,
  checkEnvironment,
  hash,
  read,
  runSuite,
  selections,
} from './stack-conformance-evidence.mjs'

const ENROLLMENT = 'conformance/stack-encrypt/v1/lifecycle-v1.enrollment.json'
const GUESTS = [
  'encrypt/wasm/stack_encrypt_guest.wasm',
  'encrypt/testdata/stack_encrypt_guest_deterministic.wasm',
]

export function lifecycleIndex(index) {
  if (index.profile !== 'lifecycle-v1')
    throw new Error(
      `Unsupported lifecycle conformance profile: ${index.profile}`,
    )
  return index
}

// Every report carries the profile's limitations, so passing evidence is
// never read without the gaps it does not cover. The Go guests are hashed
// whenever a Go suite is selected.
export function buildReport(
  index,
  selected,
  language,
  { platform, architecture, engine, hash },
) {
  lifecycleIndex(index)
  const report = {
    profile: index.profile,
    language,
    platform,
    architecture,
    engine,
    enrollment_sha256: hash(ENROLLMENT),
    lock_sha256: hash('Cargo.lock'),
    limitations: index.limitations,
    evidence: {},
  }
  if ([...selected.values()].some((suite) => suite.language === 'go'))
    report.guests = Object.fromEntries(
      GUESTS.map((name) => [name, hash(`languages/golang/${name}`)]),
    )
  return report
}

export function main(args = process.argv.slice(2)) {
  const [language = 'all'] = args
  if (args.length > 1)
    throw new Error('Usage: stack-lifecycle-conformance.mjs [rust|go|all]')
  checkEnvironment(process.env)
  if (!['linux', 'darwin'].includes(process.platform))
    throw new Error(
      'The current lifecycle profile requires a Unix heap observer; this platform is not enrolled',
    )
  const index = JSON.parse(read(ENROLLMENT))
  const selected = selections(lifecycleIndex(index), 'fast', language)
  process.env.STACK_CONFORMANCE_REQUIRED = '1'
  delete process.env.STACK_CONFORMANCE_INPUT
  delete process.env.STACK_CONFORMANCE_OUTPUT
  const metadata = JSON.parse(
    cargo(['metadata', '--locked', '--no-deps', '--format-version', '1'], true),
  )
  const report = buildReport(index, selected, language, {
    platform: process.platform,
    architecture: process.arch,
    engine: metadata.packages.find((p) => p.name === 'stack-encrypt').version,
    hash,
  })
  for (const [id, suite] of selected) {
    console.log(
      `Lifecycle conformance: ${id} (${suite.tests.size} required tests)`,
    )
    runSuite(suite)
    report.evidence[id] = [...suite.tests].sort()
  }
  console.log(JSON.stringify(report, null, 2))
  if (process.env.STACK_CONFORMANCE_REPORT_DIR) {
    mkdirSync(process.env.STACK_CONFORMANCE_REPORT_DIR, { recursive: true })
    writeFileSync(
      join(
        process.env.STACK_CONFORMANCE_REPORT_DIR,
        `lifecycle-${language}.json`,
      ),
      `${JSON.stringify(report, null, 2)}\n`,
    )
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
