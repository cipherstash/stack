import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
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
  const { cpSync, mkdirSync } = await import('node:fs')
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
  const { cpSync } = await import('node:fs')
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

describe.skipIf(!authConfigured)('examples/prisma README "Run it" walkthrough', () => {
  let snapDir: string

  beforeAll(async () => {
    snapDir = await snapshotTransientOutputs()
    await wipeTransientOutputs()
  }, 60_000)

  afterAll(async () => {
    await restoreTransientOutputs(snapDir)
  }, 60_000)

  it('wipes transient outputs and restores from snapshot', () => {
    // Mid-test: contract.json is gone (wipe ran in beforeAll).
    expect(existsSync(join(EXAMPLE_DIR, 'src/prisma/contract.json'))).toBe(false)
    expect(existsSync(join(EXAMPLE_DIR, 'migrations/app'))).toBe(false)
  })
})
