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

export function main(args = process.argv.slice(2)) {
  const [language = 'all'] = args
  if (args.length > 1)
    throw new Error('Usage: stack-lifecycle-conformance.mjs [rust|go|all]')
  checkEnvironment(process.env)
  if (!['linux', 'darwin'].includes(process.platform))
    throw new Error(
      'The current lifecycle profile requires a Unix heap observer; this platform is not enrolled',
    )
  const path = 'conformance/stack-encrypt/v1/lifecycle-profiles.json'
  const index = JSON.parse(read(path))
  const selected = selections(index, 'fast', language)
  process.env.STACK_CONFORMANCE_REQUIRED = '1'
  delete process.env.STACK_CONFORMANCE_INPUT
  delete process.env.STACK_CONFORMANCE_OUTPUT
  const metadata = JSON.parse(
    cargo(['metadata', '--locked', '--no-deps', '--format-version', '1'], true),
  )
  const report = {
    profile: 'lifecycle-v1',
    language,
    platform: process.platform,
    architecture: process.arch,
    engine: metadata.packages.find((p) => p.name === 'stack-encrypt').version,
    enrollment_sha256: hash(path),
    lock_sha256: hash('Cargo.lock'),
    limitations: index.limitations,
    evidence: {},
  }
  if (language !== 'rust') {
    report.guests = Object.fromEntries(
      [
        'encrypt/wasm/stack_encrypt_guest.wasm',
        'encrypt/testdata/stack_encrypt_guest_deterministic.wasm',
      ].map((name) => [name, hash(`languages/golang/${name}`)]),
    )
  }
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
