import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(__dirname, '../..')
const EXAMPLE_DIR = resolve(REPO_ROOT, 'examples/prisma')

const authConfigured = (() => {
  if (process.env.CS_CLIENT_ID && process.env.CS_CLIENT_KEY) return true
  const home = process.env.HOME
  if (!home) return false
  return existsSync(join(home, '.cipherstash', 'auth.json'))
})()

interface StepResult {
  readonly label: string
  readonly status: number | null
  readonly signal: NodeJS.Signals | null
  readonly stdout: string
  readonly stderr: string
  readonly error: Error | undefined
}

function describeSpawnFailure(result: StepResult): string {
  const lines = [`step \`${result.label}\` failed.`]
  if (result.error) lines.push(`  spawn error: ${result.error.message}`)
  if (result.signal) lines.push(`  killed by signal: ${result.signal}`)
  if (typeof result.status === 'number') lines.push(`  exit status: ${result.status}`)
  if (result.stderr.trim()) lines.push(`--- stderr ---\n${result.stderr.trim()}`)
  if (result.stdout.trim()) lines.push(`--- stdout ---\n${result.stdout.trim()}`)
  return lines.join('\n')
}

function runStep(
  label: string,
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs?: number; env?: NodeJS.ProcessEnv } = {},
): StepResult {
  const result: SpawnSyncReturns<Buffer> = spawnSync(cmd, args, {
    cwd: opts.cwd ?? EXAMPLE_DIR,
    timeout: opts.timeoutMs ?? 120_000,
    stdio: 'pipe',
    env: opts.env ?? process.env,
  })
  return {
    label,
    status: result.status,
    signal: result.signal,
    stdout: result.stdout?.toString() ?? '',
    stderr: result.stderr?.toString() ?? '',
    error: result.error,
  }
}

const TRANSIENT_PATHS = [
  'migrations/app',
  'src/prisma/contract.json',
  'src/prisma/contract.d.ts',
] as const

async function snapshotTransientOutputs(): Promise<string> {
  const snap = mkdtempSync(join(tmpdir(), 'prisma-readme-e2e-snap-'))
  for (const rel of TRANSIENT_PATHS) {
    const src = join(EXAMPLE_DIR, rel)
    if (!existsSync(src)) continue
    const dest = join(snap, rel)
    mkdirSync(dirname(dest), { recursive: true })
    cpSync(src, dest, { recursive: true })
  }
  return snap
}

async function restoreTransientOutputs(snap: string): Promise<void> {
  for (const rel of TRANSIENT_PATHS) {
    const src = join(snap, rel)
    const dest = join(EXAMPLE_DIR, rel)
    rmSync(dest, { recursive: true, force: true })
    if (existsSync(src)) {
      cpSync(src, dest, { recursive: true })
    }
  }
  rmSync(snap, { recursive: true, force: true })
}

async function wipeTransientOutputs(): Promise<void> {
  for (const rel of TRANSIENT_PATHS) {
    rmSync(join(EXAMPLE_DIR, rel), { recursive: true, force: true })
  }
}

interface Outcomes {
  cpEnv?: StepResult
  dockerUp?: StepResult
  pnpmInstall?: StepResult
  pnpmEmit?: StepResult
  pnpmPlan?: StepResult
  pnpmApply?: StepResult
  pnpmStart?: StepResult
}

const outcomes: Outcomes = {}
let snapDir: string

describe.skipIf(!authConfigured)('examples/prisma README "Run it" walkthrough', () => {
  beforeAll(async () => {
    snapDir = await snapshotTransientOutputs()
    await wipeTransientOutputs()

    // Step 1: cp .env.example .env
    // Run via `cp` for fidelity to the README; falls back to ENOENT spawn
    // error on Windows runners (we only target Linux/macOS in CI).
    outcomes.cpEnv = runStep('cp .env.example .env', 'cp', ['.env.example', '.env'], {
      timeoutMs: 5_000,
    })

    // Step 2: docker compose up -d
    outcomes.dockerUp = runStep(
      'docker compose up -d',
      'docker',
      ['compose', 'up', '-d', '--wait'],
      { timeoutMs: 180_000 },
    )

    // Step 3: pnpm install
    outcomes.pnpmInstall = runStep('pnpm install', 'pnpm', ['install'], {
      timeoutMs: 180_000,
    })

    // Step 4: pnpm emit
    outcomes.pnpmEmit = runStep('pnpm emit', 'pnpm', ['emit'], {
      timeoutMs: 60_000,
    })

    // Step 5: pnpm migration:plan --name initial
    outcomes.pnpmPlan = runStep(
      'pnpm migration:plan --name initial',
      'pnpm',
      ['migration:plan', '--name', 'initial'],
      { timeoutMs: 60_000 },
    )

    // Step 6: pnpm migration:apply
    outcomes.pnpmApply = runStep(
      'pnpm migration:apply',
      'pnpm',
      ['migration:apply'],
      { timeoutMs: 120_000 },
    )

    // Step 7: pnpm start
    outcomes.pnpmStart = runStep('pnpm start', 'pnpm', ['start'], {
      timeoutMs: 120_000,
    })
  }, 600_000) // 10 min total budget for the cold path

  afterAll(async () => {
    // Teardown the bundled Postgres container regardless of outcome.
    runStep(
      'docker compose down -v',
      'docker',
      ['compose', 'down', '-v'],
      { timeoutMs: 60_000 },
    )
    // Restore the transient outputs from snapshot so the working tree is clean.
    await restoreTransientOutputs(snapDir)
    // Remove the .env we copied in the walkthrough (not tracked anyway).
    rmSync(join(EXAMPLE_DIR, '.env'), { force: true })
  }, 120_000)

  it('cp .env.example .env succeeded', () => {
    const r = outcomes.cpEnv!
    expect(r.status, describeSpawnFailure(r)).toBe(0)
    expect(existsSync(join(EXAMPLE_DIR, '.env'))).toBe(true)
  })

  it('docker compose up -d succeeded and Postgres became ready', () => {
    const r = outcomes.dockerUp!
    expect(r.status, describeSpawnFailure(r)).toBe(0)
    // Compose --wait already gates on the healthcheck. Double-check by
    // exec'ing pg_isready against the container the README owns.
    const ready = runStep(
      'pg_isready',
      'docker',
      ['exec', 'cipherstash-prisma-example-pg', 'pg_isready', '-U', 'postgres', '-d', 'cipherstash_prisma_example'],
      { timeoutMs: 10_000 },
    )
    expect(ready.status, describeSpawnFailure(ready)).toBe(0)
  })

  it('pnpm install succeeded', () => {
    const r = outcomes.pnpmInstall!
    expect(r.status, describeSpawnFailure(r)).toBe(0)
  })

  it('pnpm emit succeeded and wrote contract.{json,d.ts}', () => {
    const r = outcomes.pnpmEmit!
    expect(r.status, describeSpawnFailure(r)).toBe(0)
    expect(existsSync(join(EXAMPLE_DIR, 'src/prisma/contract.json'))).toBe(true)
    expect(existsSync(join(EXAMPLE_DIR, 'src/prisma/contract.d.ts'))).toBe(true)
  })

  it('pnpm migration:plan --name initial succeeded and produced an initial migration', () => {
    const r = outcomes.pnpmPlan!
    expect(r.status, describeSpawnFailure(r)).toBe(0)
    const appDir = join(EXAMPLE_DIR, 'migrations/app')
    expect(existsSync(appDir)).toBe(true)
    const entries = readdirSync(appDir)
    // CLI names the migration `<timestamp>_initial`; assert at least one
    // entry matches that suffix.
    expect(entries.some((e) => /_initial$/.test(e))).toBe(true)
  })

  it('pnpm migration:apply succeeded', () => {
    const r = outcomes.pnpmApply!
    expect(r.status, describeSpawnFailure(r)).toBe(0)
  })

  it('pnpm start exited 0', () => {
    const r = outcomes.pnpmStart!
    expect(r.status, describeSpawnFailure(r)).toBe(0)
  })

  it('pnpm start output contains every documented codec demo heading', () => {
    const stdout = outcomes.pnpmStart!.stdout

    // Headings from README "Expected output" — every one must appear.
    const headings = [
      '--- Insert (mixed-codec round-trip) ---',
      '--- cipherstashEq (string equality) ---',
      '--- cipherstashIlike (string free-text-search) ---',
      '--- cipherstashGt (double order-and-range) ---',
      '--- cipherstashBetween (date order-and-range) ---',
      '--- cipherstashInArray (bigint equality) ---',
      '--- cipherstashInArray (boolean equality-only) ---',
      '--- cipherstashAsc (bare-column ORDER BY) ---',
    ]
    for (const heading of headings) {
      expect(stdout, `missing heading: ${heading}`).toContain(heading)
    }
  })

  it('pnpm start output contains the documented row counts and email values', () => {
    const stdout = outcomes.pnpmStart!.stdout
    const expectations = [
      'Inserted 4 rows across six cipherstash codecs.',
      'Found 1 row(s) for alice@example.com.',
      'Found 3 row(s) matching %@example.com.',
      'Found 2 user(s) with salary > 100,000.',
      'Found 3 user(s) born between 1985 and 1995.',
      'Found 2 user(s) whose accountId is in the supplied array.',
      'Found 3 user(s) with emailVerified = true.',
      'alice@example.com',
      'bob@example.com',
      'carol@example.com',
      'dave@otherorg.test',
    ]
    for (const line of expectations) {
      expect(stdout, `missing expected line: ${line}`).toContain(line)
    }
  })
})
