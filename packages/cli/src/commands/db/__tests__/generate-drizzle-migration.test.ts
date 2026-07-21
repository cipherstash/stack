import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
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

// node:fs stays REAL by default — the generator's own writes, the bundled-SQL
// reads, and cleanup all need it. We only need a seam on `writeFileSync` to
// simulate the SQL-bundle write failing, so route it through a spy that
// delegates to the real implementation (reset in beforeEach) and is overridden
// only in the write-failure test.
const fsWrite = vi.hoisted(() => ({
  real: (() => {
    throw new Error('fsWrite.real not initialised')
  }) as typeof import('node:fs').writeFileSync,
  spy: vi.fn(),
}))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  fsWrite.real = actual.writeFileSync
  return { ...actual, default: actual, writeFileSync: fsWrite.spy }
})

// The `--latest` path calls `downloadEqlSql`; stub just that export so we can
// make the network fetch reject. Everything else in the installer module
// (including the real `loadBundledEqlSql` the other tests rely on) stays real.
const downloadMock = vi.hoisted(() => vi.fn())
vi.mock('@/installer/index.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/installer/index.js')>()),
  downloadEqlSql: downloadMock,
}))

// Pin the package manager so the argv assertion below is exact. Detection reads
// the lockfile in cwd and npm_config_user_agent, both of which vary by how the
// suite was launched. The runner MAPPING stays real — `pnpm` + `['exec', …]` is
// part of what's being asserted, so mocking it would defeat the test.
vi.mock('@/commands/init/utils.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/commands/init/utils.js')>()),
  detectPackageManager: () => 'pnpm',
}))

const { generateDrizzleMigration } = await import('../install.js')

const spinner = p.spinner()

beforeEach(() => {
  // Default: `writeFileSync` behaves exactly like the real thing. Tests that
  // need it to fail override the implementation for their own scope.
  fsWrite.spy.mockImplementation(fsWrite.real)
})

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
    // `''` is not nullish, so it slips past `options.name ?? DEFAULT` and hits
    // the regex, where `+` rejects it — `--name ''` aborts, it does NOT fall
    // back to `install-eql`. The one input where "empty" and "absent" diverge.
    ['an empty string', ''],
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
    // The whole argv, exactly — not `toContain` checks, which would still pass
    // if the runner prefix (`exec`) were dropped and drizzle-kit ran under the
    // wrong resolver. DEFECT 1: name and out are discrete inert tokens in an
    // array, never interpolated into a shell string. DEFECT 2: `--out` is
    // actually passed, so drizzle-kit writes where step 2 then looks. The
    // project-local `exec` form (not `dlx`) is asserted so a regression back to
    // download-and-run — which resolves a different drizzle.config.ts — fails.
    expect(command).toBe('pnpm')
    expect(argv).toEqual([
      'exec',
      'drizzle-kit',
      'generate',
      '--custom',
      '--name=add-eql',
      `--out=${out}`,
    ])

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

  it('reports the spawn error when drizzle-kit cannot be launched', async () => {
    // spawnSync's ENOENT shape: null status, no captured stderr, `error` set.
    // `result.stderr?.trim()` is undefined, so the message falls through to the
    // second arm (`result.error?.message`) — the realistic "drizzle-kit isn't
    // installed" case. If the `?.` on stderr were dropped this shape would
    // throw a TypeError instead of reporting.
    spawnMock.mockReturnValue({
      status: null,
      stdout: null,
      stderr: null,
      error: Object.assign(new Error('spawnSync pnpm ENOENT'), {
        code: 'ENOENT',
      }),
    })

    await expect(
      generateDrizzleMigration(spinner, { out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith('spawnSync pnpm ENOENT')
    expect(clack.log.info).toHaveBeenCalledWith(
      'Make sure drizzle-kit is installed: npm install -D drizzle-kit',
    )
  })

  it('falls back to the exit status when there is no stderr or spawn error', async () => {
    // Third arm of the fallback chain: non-zero status, empty stderr, no
    // `error`. The user still gets a message instead of a blank error line.
    spawnMock.mockReturnValue({ status: 2, stdout: '', stderr: '' })

    await expect(
      generateDrizzleMigration(spinner, { out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(
      'drizzle-kit exited with status 2.',
    )
  })

  it('defaults --out to an absolute drizzle/ when the flag is omitted', async () => {
    // Widest blast radius in the diff: because `--out` is always appended, a
    // flag-less invocation has its drizzle.config.ts `out` overridden by
    // `<cwd>/drizzle`. The dry-run preview reaches that arm without touching
    // the filesystem or spawning.
    await generateDrizzleMigration(spinner, { dryRun: true })
    expect(clack.note).toHaveBeenCalledWith(
      expect.stringContaining(`--out=${resolve('drizzle')}`),
      'Dry Run',
    )
  })

  it('points at --out when the generated migration is not where we looked', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    // drizzle-kit "succeeds" but wrote to its drizzle.config.ts `out`, not ours,
    // so step 2 finds nothing and aborts with the remediation hint (defect 2).
    spawnMock.mockReturnValue({ status: 0, stdout: '', stderr: '' })

    await expect(
      generateDrizzleMigration(spinner, { out }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.info).toHaveBeenCalledWith(
      'If your drizzle.config.ts writes elsewhere, pass --out <dir> so it matches.',
    )
  })

  it('removes the scaffolded migration when writing the SQL fails', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    const scaffolded = join(out, '0000_install-eql.sql')
    // drizzle-kit scaffolds an empty custom migration where we look.
    spawnMock.mockImplementation(() => {
      fsWrite.real(scaffolded, '')
      return { status: 0, stdout: '', stderr: '' }
    })
    // Throw only on the big bundle write, letting the empty scaffold through.
    fsWrite.spy.mockImplementation(((path, data, ...rest) => {
      if (typeof data === 'string' && data.includes('cs_migrations')) {
        throw new Error('EACCES: permission denied')
      }
      return fsWrite.real(
        path as string,
        data as string,
        ...(rest as unknown[]),
      )
    }) as typeof import('node:fs').writeFileSync)

    await expect(
      generateDrizzleMigration(spinner, { out }),
    ).rejects.toBeInstanceOf(CliExit)
    // Without cleanup, an empty scaffolded migration survives and
    // `drizzle-kit migrate` applies and records it — a silent no-op migration.
    expect(existsSync(scaffolded)).toBe(false)
    expect(clack.log.error).toHaveBeenCalledWith('EACCES: permission denied')
  })

  it('cleans up the scaffold when --latest cannot fetch the SQL', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    const scaffolded = join(out, '0000_install-eql.sql')
    spawnMock.mockImplementation(() => {
      fsWrite.real(scaffolded, '')
      return { status: 0, stdout: '', stderr: '' }
    })
    // A network failure (rate limit / offline) is the likeliest real trip here.
    downloadMock.mockRejectedValueOnce(new Error('403 rate limited'))

    await expect(
      generateDrizzleMigration(spinner, { out, latest: true }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(existsSync(scaffolded)).toBe(false)
    expect(clack.log.error).toHaveBeenCalledWith('403 rate limited')
  })
})
