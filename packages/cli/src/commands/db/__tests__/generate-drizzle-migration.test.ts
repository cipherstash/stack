import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as p from '@clack/prompts'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CliExit } from '../../../cli/exit.js'
import { messages } from '../../../messages.js'

// clack is chrome — silence it and spy on the channels the generator reports
// through. The spinner instance doubles as the `s` argument.
const clack = vi.hoisted(() => ({
  spinnerInstance: { start: vi.fn(), stop: vi.fn() },
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
  intro: vi.fn(),
  note: vi.fn(),
  outro: vi.fn(),
}))
vi.mock('@clack/prompts', () => ({
  spinner: vi.fn(() => clack.spinnerInstance),
  log: clack.log,
  intro: clack.intro,
  note: clack.note,
  outro: clack.outro,
}))

// Only the child process is faked — everything else (fs, bundled SQL) is real.
const spawnMock = vi.hoisted(() => vi.fn())
vi.mock('node:child_process', () => ({ spawnSync: spawnMock }))

const { generateDrizzleMigration } = await import('../install.js')

const spinner = p.spinner()

afterEach(() => {
  vi.clearAllMocks()
})

/**
 * The v2 (`eql install --drizzle`) generator. Both regressions pinned here are
 * invocation-level: an unvalidated `--name` reaching a shell string, and
 * `--out` being computed for the search but never handed to drizzle-kit.
 */
describe('generateDrizzleMigration', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'stash-v2-drizzle-migration-'))
  })
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('rejects a migration name with unsafe characters before spawning', async () => {
    await expect(
      generateDrizzleMigration(spinner, {
        name: 'x; rm -rf ~',
        out: join(tmp, 'drizzle'),
      }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(messages.eql.migrationBadName)
    expect(spawnMock).not.toHaveBeenCalled()
  })

  it.each([
    ['command substitution', 'a$(whoami)'],
    ['backticks', 'a`id`'],
    ['a space', 'add eql'],
    ['a path separator', '../escape'],
  ])('rejects %s in --name', async (_label, name) => {
    await expect(
      generateDrizzleMigration(spinner, { name, out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(spawnMock).not.toHaveBeenCalled()
  })

  it('rejects an unsafe name in a dry run too (validation precedes the preview)', async () => {
    await expect(
      generateDrizzleMigration(spinner, { name: 'x; ls', dryRun: true }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.note).not.toHaveBeenCalled()
  })

  it('passes --name and --out to drizzle-kit as argv (no shell) and writes the SQL', async () => {
    const out = join(tmp, 'db', 'migrations')
    mkdirSync(out, { recursive: true })
    // Stand in for drizzle-kit scaffolding an empty custom migration.
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0000_add-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await generateDrizzleMigration(spinner, { name: 'add-eql', out })

    expect(spawnMock).toHaveBeenCalledTimes(1)
    const [command, argv] = spawnMock.mock.calls[0]
    // argv array, never a shell string — name/out are discrete inert tokens.
    expect(typeof command).toBe('string')
    expect(Array.isArray(argv)).toBe(true)
    expect(argv).toContain('drizzle-kit')
    expect(argv).toContain('--name=add-eql')
    // DEFECT 2: --out must actually be passed, so drizzle-kit writes where we
    // then look.
    expect(argv).toContain(`--out=${out}`)

    const written = readFileSync(join(out, '0000_add-eql.sql'), 'utf-8')
    expect(written).toContain('cs_migrations')
  })

  it('includes --out in the dry-run preview', async () => {
    const out = join(tmp, 'custom-out')
    await generateDrizzleMigration(spinner, { dryRun: true, out })
    expect(spawnMock).not.toHaveBeenCalled()
    expect(clack.note).toHaveBeenCalledWith(
      expect.stringContaining(`--out=${out}`),
      'Dry Run',
    )
  })

  it('aborts with CliExit when drizzle-kit exits non-zero', async () => {
    spawnMock.mockReturnValue({ status: 1, stdout: '', stderr: 'boom' })
    await expect(
      generateDrizzleMigration(spinner, { out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith('boom')
  })
})
