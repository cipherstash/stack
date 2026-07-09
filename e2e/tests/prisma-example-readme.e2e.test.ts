import { spawnSync } from 'node:child_process'
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs'
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
  // `stash auth login` stores either an `auth.json` (legacy PKCE flow) or a
  // `device.json` (device-code flow) under the profile directory; both let
  // the stack client authenticate without CS_* env vars.
  return (
    existsSync(join(home, '.cipherstash', 'auth.json')) ||
    existsSync(join(home, '.cipherstash', 'device.json'))
  )
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
  if (typeof result.status === 'number')
    lines.push(`  exit status: ${result.status}`)
  if (result.stderr.trim())
    lines.push(`--- stderr ---\n${result.stderr.trim()}`)
  if (result.stdout.trim())
    lines.push(`--- stdout ---\n${result.stdout.trim()}`)
  return lines.join('\n')
}

function runStep(commandLine: string, timeoutMs: number): StepResult {
  const result = spawnSync('bash', ['-c', commandLine], {
    cwd: EXAMPLE_DIR,
    timeout: timeoutMs,
    stdio: 'pipe',
    env: process.env,
  })
  return {
    label: commandLine,
    status: result.status,
    signal: result.signal,
    stdout: result.stdout?.toString() ?? '',
    stderr: result.stderr?.toString() ?? '',
    error: result.error,
  }
}

// `.env` is included so a developer's real credentials file survives the
// walkthrough: the README's `cp .env.example .env` step overwrites it, and
// without the snapshot the teardown would delete it outright. The snapshot
// captures it before the run and the restore puts the original back.
const TRANSIENT_PATHS = [
  'migrations/app',
  'src/prisma/contract.json',
  'src/prisma/contract.d.ts',
  '.env',
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

// Parses the bash code fence directly under `## Run it` in the example's
// README. Strips inline ` # ...` comments, trims, drops blank lines, and
// preserves order. Throws with a descriptive message if the heading or
// fence isn't found — that way a malformed README surfaces at test-collection
// time, not as an opaque parse error mid-run.
function parseRunItCommands(readme: string): string[] {
  const match = readme.match(/^## Run it\b[\s\S]*?\n```bash\n([\s\S]*?)\n```/m)
  if (!match) {
    throw new Error(
      'parseRunItCommands: could not locate the bash code fence under `## Run it` in the README. ' +
        'Check examples/prisma/README.md structure (expected `## Run it` heading followed by a ```bash fenced block).',
    )
  }
  return match[1]!
    .split('\n')
    .map((line) => line.replace(/\s+#\s.*$/, '').trim())
    .filter((line) => line.length > 0)
}

// Interactive commands the test must skip in CI. `stash auth login` is PKCE;
// it blocks on a browser. Exact-match by design — if the README's wording
// drifts, the test fails loudly rather than silently over-skipping.
const SKIP_COMMANDS = new Set<string>(['stash auth login'])

const TIMEOUT_BY_PREFIX: Array<readonly [RegExp, number]> = [
  [/^cp\b/, 5_000],
  [/^docker compose up\b/, 180_000],
  [/^pnpm install\b/, 180_000],
  [/^pnpm migration:apply\b/, 180_000],
  [/^pnpm start\b/, 180_000],
]
const DEFAULT_TIMEOUT_MS = 60_000
function timeoutFor(line: string): number {
  for (const [re, ms] of TIMEOUT_BY_PREFIX) if (re.test(line)) return ms
  return DEFAULT_TIMEOUT_MS
}

// Parse the README at module load (test collection time) so per-step `it()`s
// can be registered dynamically. The README is in-repo and small; a sync read
// here is the right call.
const README_COMMANDS = parseRunItCommands(
  readFileSync(resolve(EXAMPLE_DIR, 'README.md'), 'utf8'),
)
const EXECUTED_COMMANDS = README_COMMANDS.filter(
  (line) => !SKIP_COMMANDS.has(line),
)

const outcomes = new Map<string, StepResult>()
let snapDir: string

describe.skipIf(!authConfigured)(
  'examples/prisma README "Run it" walkthrough',
  () => {
    beforeAll(async () => {
      snapDir = await snapshotTransientOutputs()
      await wipeTransientOutputs()

      // Drive the walkthrough straight from the parsed README. `bash -c` keeps
      // fidelity with what a user actually types — no argv tokenizer needed,
      // future README evolutions (operators, quoting) Just Work.
      for (const line of README_COMMANDS) {
        if (SKIP_COMMANDS.has(line)) {
          console.log(`[readme-walkthrough] skip: ${line}`)
          continue
        }
        outcomes.set(line, runStep(line, timeoutFor(line)))
      }
    }, 600_000) // 10 min total budget for the cold path

    afterAll(async () => {
      // Teardown the bundled Postgres container regardless of outcome.
      runStep('docker compose down -v', 60_000)
      // Restore the transient outputs from snapshot so the working tree is
      // clean. `.env` is part of the snapshot: the walkthrough's
      // `cp .env.example .env` overwrote it, and the restore brings back the
      // developer's original (or removes the copy when none existed before).
      await restoreTransientOutputs(snapDir)
    }, 120_000)

    // Per-step exit-zero assertion, registered once per non-skipped README line.
    it.each(EXECUTED_COMMANDS)('README "Run it" step exited 0: %s', (line) => {
      const r = outcomes.get(line)
      expect(
        r,
        `no outcome recorded for \`${line}\` — beforeAll did not run this step`,
      ).toBeDefined()
      expect(r!.status, describeSpawnFailure(r!)).toBe(0)
    })
  },
)
