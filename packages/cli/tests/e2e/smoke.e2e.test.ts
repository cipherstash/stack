import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { messages } from '../../src/messages.js'
import { render } from '../helpers/pty.js'

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
    expect(r.output).toContain('db install')
    // dotenv v17 prints an `injected env (N) from …` banner on every
    // `config()` call unless `quiet: true` is passed. Guard against that
    // noise regressing back into the CLI's stdout (it also destabilises the
    // PTY output capture these e2e tests rely on).
    expect(r.output).not.toContain('injected env')
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

  it('db migrate is a stub that exits 0 with a "not yet implemented" warning', async () => {
    const r = render(['db', 'migrate'])
    const { exitCode } = await r.exit
    expect(exitCode).toBe(0)
    // `migrateNotImplemented` is a runner-aware factory; the runner-agnostic
    // suffix is the stable assertion target.
    expect(r.output).toContain('stash db migrate" is not yet implemented.')
  })
})
