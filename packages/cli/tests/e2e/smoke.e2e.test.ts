import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'
import { run } from '../helpers/run.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(
  readFileSync(resolve(__dirname, '../../package.json'), 'utf-8'),
) as { version: string }

describe('stash CLI — non-interactive smoke', () => {
  it('--help prints the help banner and exits 0', async () => {
    const r = render(['--help'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    expect(r.output).toContain(messages.cli.versionBannerPrefix)
    expect(r.output).toContain(messages.cli.usagePrefix)
    // Command-list items — these are the literal command names users type, not
    // copy strings, so they stay inline.
    expect(r.output).toContain('init')
    expect(r.output).toContain('eql install')
    expect(r.output).toContain('eql upgrade')
    expect(r.output).toContain('eql status')
    // The dotenv "injected env" banner regression guard lives in the
    // dedicated test below — this cwd has no .env file, so a bare
    // `not.toContain('injected env')` here would pass vacuously.
  })

  it('suppresses dotenv v17\'s "injected env" banner when a .env file exists in cwd', async () => {
    // dotenv v17 prints an `injected env (N) from …` banner to stdout on
    // every `config()` call that actually injects a variable, unless
    // `quiet: true` is passed. The repo has no `.env` anywhere, so exercising
    // this requires a real .env file in the spawned process's cwd — without
    // it, `config()` never finds anything to inject and the banner can never
    // appear regardless of whether `quiet: true` is present in the CLI.
    const tmpDir = mkdtempSync(join(tmpdir(), 'stash-dotenv-quiet-'))
    try {
      writeFileSync(join(tmpDir, '.env'), 'STASH_DOTENV_QUIET_TEST=1\n')
      const r = await run(['--version'], { cwd: tmpDir })
      expect(r.exitCode).toBe(0)
      expect(r.output).toContain(pkg.version)
      expect(r.output).not.toContain('injected env')
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('--version prints the package version', async () => {
    const r = render(['--version'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    expect(r.output.trim()).toContain(pkg.version)
  })

  it('unknown top-level command exits 1 with help', async () => {
    const r = render(['definitely-not-a-command'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(1)
    // Stable phrase + user-supplied token asserted separately so a copy tweak
    // around the wording doesn't break the test.
    expect(r.output).toContain(messages.cli.unknownCommand)
    expect(r.output).toContain('definitely-not-a-command')
    expect(r.output).toContain(messages.cli.usagePrefix)
  })

  it('auth with no subcommand prints auth help and exits 0', async () => {
    const r = render(['auth'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    expect(r.output).toContain(messages.auth.usagePrefix)
    expect(r.output).toContain('login')
  })

  it('auth bogus-sub exits 1 with auth help', async () => {
    const r = render(['auth', 'bogus-sub'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(1)
    expect(r.output).toContain(messages.auth.unknownSubcommand)
    expect(r.output).toContain('bogus-sub')
  })

  it('db bogus-sub exits 1 with help', async () => {
    const r = render(['db', 'bogus-sub'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(1)
    expect(r.output).toContain(messages.db.unknownSubcommand)
    expect(r.output).toContain('bogus-sub')
  })

  it('eql bogus-sub exits 1 with help', async () => {
    const r = render(['eql', 'bogus-sub'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(1)
    expect(r.output).toContain(messages.eql.unknownSubcommand)
    expect(r.output).toContain('bogus-sub')
  })

  // `--migration` without `--supabase` fails flag validation before any I/O
  // or prompt, so these two cases can observe the install entry path
  // deterministically without a database.
  it('db install still works as a deprecated alias and warns', async () => {
    const r = render(['db', 'install', '--migration'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(1)
    // Runner-aware factory — assert on the runner-agnostic suffix.
    expect(r.output).toContain('stash db install" is deprecated')
    expect(r.output).toContain('eql install" instead')
    // The alias reaches the real install command (its flag validation ran).
    expect(r.output).toContain('requires `--supabase`')
  })

  it('eql install routes to the install command without a deprecation warning', async () => {
    const r = render(['eql', 'install', '--migration'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(1)
    expect(r.output).not.toContain('is deprecated')
    expect(r.output).toContain('requires `--supabase`')
  })

  it('db migrate is a stub that exits 0 with a "not yet implemented" warning', async () => {
    const r = render(['db', 'migrate'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    // `migrateNotImplemented` is a runner-aware factory; the runner-agnostic
    // suffix is the stable assertion target.
    expect(r.output).toContain('stash db migrate" is not yet implemented.')
  })

  // The two cases below exercise `run()` directly rather than `render()`.
  // Every existing `run()` consumer only asserted `exitCode === 0`
  // (runner-aware-help.e2e.test.ts) and every exit-1 case above still went
  // through `render()`, so `run()`'s actual purpose — correctly propagating
  // a non-zero/null exit code instead of masking it — was untested by
  // anything that used `run()`.
  it('run(): surfaces a non-zero exit code + error output for an unknown command', async () => {
    const r = await run(['definitely-not-a-command'])
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain(messages.cli.unknownCommand)
    expect(r.output).toContain('definitely-not-a-command')
  })

  it('run(): splits stdout/stderr into independent channels on a failure path', async () => {
    // The unknown-command error is written via `console.error` (stderr); the
    // HELP banner that follows it is written via `console.log` (stdout).
    // Assert on the dedicated `stdout`/`stderr` fields — not just the
    // combined `output` — so a regression that wired both `data` handlers
    // to the same buffer would be caught.
    const r = await run(['definitely-not-a-command'])
    expect(r.stderr).toContain(messages.cli.unknownCommand)
    expect(r.stderr).not.toContain(messages.cli.usagePrefix)
    expect(r.stdout).toContain(messages.cli.usagePrefix)
    expect(r.stdout).not.toContain(messages.cli.unknownCommand)
  })
})
