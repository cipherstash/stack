import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CliExit } from '../../../cli/exit.js'
import { messages } from '../../../messages.js'
import { buildEqlV3MigrationSql, eqlMigrationCommand } from '../migration.js'

// clack is chrome — silence it and spy on the error/note channels the command
// reports through.
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

// Stub the drizzle-kit scaffold — only the child process is faked.
const spawnMock = vi.hoisted(() => vi.fn())
vi.mock('node:child_process', () => ({ spawnSync: spawnMock }))

// `node:fs` stays REAL by default (so `loadBundledEqlSql` reads the bundled SQL
// and the tmpdir writes/reads work) — only `writeFileSync` is a spy that
// delegates to the real impl, so the cleanup test can make just the SQL write
// throw without touching everything else. `beforeEach` restores the delegating
// default after `clearAllMocks`.
const fsWrite = vi.hoisted(() => ({
  // Populated by the `node:fs` mock factory below (which always runs before any
  // test). The placeholder throws rather than being a type-erased `undefined`,
  // so a missed initialisation fails loudly instead of calling `undefined()`.
  real: (() => {
    throw new Error(
      'fsWrite.real not initialised: node:fs mock factory did not run',
    )
  }) as typeof import('node:fs').writeFileSync,
  spy: vi.fn(),
}))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  fsWrite.real = actual.writeFileSync
  return { ...actual, default: actual, writeFileSync: fsWrite.spy }
})

// `printNextSteps` lives in the install module, which drags in `pg`. Stub it;
// the two helpers we reuse (`findGeneratedMigration`, `cleanupMigrationFile`)
// stay real and act on the tmpdir.
vi.mock('../../db/install.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../db/install.js')>()
  return { ...actual, printNextSteps: vi.fn() }
})

beforeEach(() => {
  fsWrite.spy.mockImplementation(fsWrite.real)
})
afterEach(() => {
  vi.clearAllMocks()
})

/**
 * `buildEqlV3MigrationSql` is the pure core: it assembles the migration from the
 * CLI's bundled v3 install SQL, the optional Supabase grants, and the
 * `cs_migrations` tracking schema.
 */
describe('buildEqlV3MigrationSql', () => {
  it('emits the EQL v3 install bundle and the cs_migrations tracking schema', () => {
    const sql = buildEqlV3MigrationSql({ supabase: false })
    expect(sql).toContain('EQL v3 schema creation')
    expect(sql).toContain('eql_v3')
    expect(sql).toContain('cs_migrations')
  })

  it('omits the Supabase role grants without --supabase', () => {
    const sql = buildEqlV3MigrationSql({ supabase: false })
    expect(sql).not.toContain('TO anon, authenticated, service_role')
    expect(sql).not.toContain('-- Supabase role grants')
  })

  it('appends the eql_v3 + eql_v3_internal grants with --supabase', () => {
    const sql = buildEqlV3MigrationSql({ supabase: true })
    expect(sql).toContain('-- Supabase role grants')
    expect(sql).toContain(
      'GRANT USAGE ON SCHEMA eql_v3 TO anon, authenticated, service_role',
    )
    expect(sql).toContain(
      'GRANT USAGE ON SCHEMA eql_v3_internal TO anon, authenticated, service_role',
    )
  })

  it('orders the bundle: schema creation → grants → tracking schema', () => {
    // Order is the contract: `GRANT ... ON SCHEMA eql_v3` against a not-yet-
    // created schema is a hard error at migrate time, so `toContain` isn't
    // enough — the offsets must be monotonic.
    const sql = buildEqlV3MigrationSql({ supabase: true })
    const schemaAt = sql.indexOf('EQL v3 schema creation')
    const grantAt = sql.indexOf('GRANT USAGE ON SCHEMA eql_v3 TO')
    const trackingAt = sql.indexOf(
      '-- CipherStash encryption-migration tracking schema.',
    )
    expect(schemaAt).toBeGreaterThanOrEqual(0)
    expect(grantAt).toBeGreaterThan(schemaAt)
    expect(trackingAt).toBeGreaterThan(grantAt)
  })
})

describe('eqlMigrationCommand — target selection', () => {
  it.each([
    ['no target', {}, () => messages.eql.migrationNeedsTarget],
    [
      'both targets',
      { drizzle: true, prisma: true },
      () => messages.eql.migrationOneTarget,
    ],
    [
      '--prisma',
      { prisma: true },
      () => messages.eql.migrationPrismaUnavailable,
    ],
    // `--supabase` is a modifier, not a target.
    [
      '--supabase alone',
      { supabase: true },
      () => messages.eql.migrationNeedsTarget,
    ],
  ])('exits 1 with an actionable message for %s', async (_label, opts, msg) => {
    await expect(eqlMigrationCommand(opts)).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(msg())
    expect(spawnMock).not.toHaveBeenCalled()
  })
})

describe('eqlMigrationCommand — Drizzle', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'stash-eql-migration-'))
  })
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('rejects a migration name with unsafe characters before spawning', async () => {
    await expect(
      eqlMigrationCommand({ drizzle: true, name: 'a b; rm -rf /' }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(messages.eql.migrationBadName)
    expect(spawnMock).not.toHaveBeenCalled()
  })

  it('dry run neither spawns drizzle-kit nor creates the out directory', async () => {
    const out = join(tmp, 'drizzle')
    await eqlMigrationCommand({ drizzle: true, dryRun: true, out })
    expect(spawnMock).not.toHaveBeenCalled()
    expect(existsSync(out)).toBe(false)
    expect(clack.note).toHaveBeenCalledWith(
      expect.stringContaining(
        'drizzle-kit generate --custom --name=install-eql',
      ),
      'Dry Run',
    )
  })

  it('dry run says the grants would be included under --supabase', async () => {
    await eqlMigrationCommand({
      drizzle: true,
      dryRun: true,
      supabase: true,
      out: join(tmp, 'd'),
    })
    expect(clack.note).toHaveBeenCalledWith(
      expect.stringContaining('(with Supabase grants)'),
      'Dry Run',
    )
  })

  it('threads --name/--out into drizzle-kit (as argv, no shell) and writes the SQL', async () => {
    const out = join(tmp, 'db', 'migrations')
    mkdirSync(out, { recursive: true })
    // Stand in for drizzle-kit scaffolding an empty custom migration.
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0000_add-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, name: 'add-eql', out })

    // argv array, never a shell string — the name/out are discrete tokens.
    const [, argv] = spawnMock.mock.calls[0]
    expect(argv).toContain('drizzle-kit')
    expect(argv).toContain('--name=add-eql')
    expect(argv).toContain(`--out=${out}`)

    const written = readFileSync(join(out, '0000_add-eql.sql'), 'utf-8')
    expect(written).toContain('EQL v3 schema creation')
    expect(written).toContain('cs_migrations')
  })

  it('aborts (exit 1) when drizzle-kit exits non-zero', async () => {
    spawnMock.mockReturnValue({ status: 1, stdout: '', stderr: 'boom' })
    await expect(
      eqlMigrationCommand({ drizzle: true, out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith('boom')
  })

  it('removes the scaffolded migration when writing the SQL fails', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    const scaffolded = join(out, '0000_install-eql.sql')
    spawnMock.mockImplementation(() => {
      // drizzle-kit's empty custom migration (delegates to real write).
      fsWrite.real(scaffolded, '')
      return { status: 0, stdout: '', stderr: '' }
    })
    // Throw on the SQL write specifically (the big bundle), letting the empty
    // scaffold write through — robust to call order.
    fsWrite.spy.mockImplementation(((path: string, data: unknown, ...rest) => {
      if (typeof data === 'string' && data.includes('EQL v3 schema creation')) {
        throw new Error('EACCES: permission denied')
      }
      return fsWrite.real(path, data as string, ...(rest as []))
    }) as typeof import('node:fs').writeFileSync)

    await expect(
      eqlMigrationCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)

    // The empty scaffold must not survive — drizzle-kit would happily run it.
    expect(existsSync(scaffolded)).toBe(false)
    expect(clack.log.error).toHaveBeenCalledWith('EACCES: permission denied')
  })
})
