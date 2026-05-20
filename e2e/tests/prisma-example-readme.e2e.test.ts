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

describe.skipIf(!authConfigured)('examples/prisma README "Run it" walkthrough', () => {
  it('placeholder — replaced in subsequent tasks', () => {
    expect(authConfigured).toBe(true)
  })
})
