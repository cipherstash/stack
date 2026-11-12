import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs, promisify } from 'node:util'
import { createRealDriver } from './real-driver.mjs'
import { run } from './run.mjs'

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    migrator: { type: 'string' },
    fake: { type: 'string' },
    output: { type: 'string' },
    stack: { type: 'string' },
  },
  strict: true,
})
const command = values.migrator ?? ''
const fakeMigration = values.fake
if (
  (!command && !fakeMigration) ||
  (command && fakeMigration) ||
  values.output === '' ||
  values.stack === ''
)
  throw Error('Usage: harness:run --migrator <command> | --fake <variant>')
const id = randomUUID()
const root = resolve(fileURLToPath(new URL('../../..', import.meta.url)))
const output = resolve(values.output ?? `.migration-harness-runs/${id}`)
await mkdir(output, { recursive: true })
const manifest = {
  stack: values.stack ?? '^1.2.1',
  guideHash: null,
  fixtureRevision: (
    await promisify(execFile)('git', ['rev-parse', 'HEAD'], { cwd: root })
  ).stdout.trim(),
  agents: {
    // A deterministic Fake Migrator Run must not read as real agent evidence.
    migrator: fakeMigration ? `fake:${fakeMigration}` : command,
    model: fakeMigration ? 'fake-migrator' : 'command-adapter',
    limits: { timeMs: 40 * 60 * 1000, turns: 200 },
    allowlist: ['brokered isolated exec'],
  },
  isolation: { backend: 'linux-ptrace-network-namespace', verified: false },
}
const credentials = Object.fromEntries(
  [
    'CS_WORKSPACE_CRN',
    'CS_CLIENT_ID',
    'CS_CLIENT_KEY',
    'CS_CLIENT_ACCESS_KEY',
    'CS_CTS_HOST',
    'CS_ZEROKMS_HOST',
  ].flatMap((key) => {
    const value = process.env[key]
    return typeof value === 'string' && value ? [[key, value]] : []
  }),
)
let driver, isolation
try {
  const { createIsolation } = await import('../isolation.mjs')
  isolation = await createIsolation({})
  driver = createRealDriver({
    id,
    root,
    output,
    command,
    fakeMigration,
    isolation,
    credentials,
    manifest,
  })
} catch (error) {
  const message = error instanceof Error ? error.message : String(error)
  const unavailable = async () => {
    throw Error(`Isolation backend unavailable: ${message}`)
  }
  driver = {
    provision: unavailable,
    installUnmigrated: unavailable,
    initializeLegacyData: unavailable,
    snapshot: unavailable,
    migrate: unavailable,
    friction: unavailable,
    installAppHost: unavailable,
    behaviour: unavailable,
  }
}
try {
  const report = await run({ id, manifest, driver, supervision: isolation })
  await writeFile(
    resolve(output, 'run-report.json'),
    `${JSON.stringify(report, null, 2)}\n`,
  )
  console.error(`${report.outcome}: ${output}`)
  process.exitCode =
    report.outcome === 'pass' || report.outcome === 'friction-only' ? 0 : 1
} finally {
  if ('close' in driver) await driver.close()
}
