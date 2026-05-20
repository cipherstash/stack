import { spawnSync, type SpawnSyncReturns } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
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
const EXECUTED_COMMANDS = README_COMMANDS.filter((line) => !SKIP_COMMANDS.has(line))

const outcomes = new Map<string, StepResult>()
let snapDir: string

describe.skipIf(!authConfigured)('examples/prisma README "Run it" walkthrough', () => {
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
      outcomes.set(line, runStep(line, 'bash', ['-c', line], { timeoutMs: timeoutFor(line) }))
    }
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

  // Per-step exit-zero assertion, registered once per non-skipped README line.
  it.each(EXECUTED_COMMANDS)('README "Run it" step exited 0: %s', (line) => {
    const r = outcomes.get(line)
    expect(r, `no outcome recorded for \`${line}\` — beforeAll did not run this step`).toBeDefined()
    expect(r!.status, describeSpawnFailure(r!)).toBe(0)
  })

  // Side-effect assertions: observe the final state after the walkthrough.
  // Not driven by README parse — these guard against "exit 0 but produced
  // no output" regressions that pure exit-zero checks can't catch.
  it('cp produced examples/prisma/.env', () => {
    expect(existsSync(join(EXAMPLE_DIR, '.env'))).toBe(true)
  })

  it('Postgres container is ready', () => {
    const ready = runStep(
      'pg_isready',
      'docker',
      ['exec', 'cipherstash-prisma-example-pg', 'pg_isready', '-U', 'postgres', '-d', 'cipherstash_prisma_example'],
      { timeoutMs: 10_000 },
    )
    expect(ready.status, describeSpawnFailure(ready)).toBe(0)
  })

  it('pnpm emit wrote contract.{json,d.ts}', () => {
    expect(existsSync(join(EXAMPLE_DIR, 'src/prisma/contract.json'))).toBe(true)
    expect(existsSync(join(EXAMPLE_DIR, 'src/prisma/contract.d.ts'))).toBe(true)
  })

  it('pnpm migration:plan produced an initial migration', () => {
    const appDir = join(EXAMPLE_DIR, 'migrations/app')
    expect(existsSync(appDir)).toBe(true)
    const entries = readdirSync(appDir)
    expect(entries.some((e) => /_initial$/.test(e))).toBe(true)
  })

  it('pnpm start output contains every documented codec demo heading', () => {
    const startLine = README_COMMANDS.find((l) => /^pnpm start\b/.test(l))
    expect(startLine, '`pnpm start` not found in README walkthrough').toBeDefined()
    const stdout = outcomes.get(startLine!)?.stdout ?? ''

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
    const startLine = README_COMMANDS.find((l) => /^pnpm start\b/.test(l))
    expect(startLine, '`pnpm start` not found in README walkthrough').toBeDefined()
    const stdout = outcomes.get(startLine!)?.stdout ?? ''
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
