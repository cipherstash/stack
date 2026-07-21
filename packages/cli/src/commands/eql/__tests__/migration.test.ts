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
import { printNextSteps } from '../../db/install.js'
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

  // drizzle-kit emits an un-runnable in-place `ALTER COLUMN ... SET DATA TYPE`
  // when a plaintext column is changed to an encrypted one. `eql install
  // --drizzle` has always swept the out directory for these; the v3
  // migration-first path must do the same, or a v3 user is left with a broken
  // migration and nothing to fix it (#693).
  it('rewrites a sibling migration with a broken v3 ALTER COLUMN', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    const sibling = join(out, '0001_encrypt-email.sql')
    writeFileSync(
      sibling,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_text_search";\n',
    )
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0002_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, out })

    const rewritten = readFileSync(sibling, 'utf-8')
    expect(rewritten).toContain(
      'ALTER TABLE "users" ADD COLUMN "email__cipherstash_tmp" "public"."eql_v3_text_search";',
    )
    expect(rewritten).not.toContain('SET DATA TYPE')
  })

  it('does not rewrite the EQL install migration it just generated', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    const generated = join(out, '0000_install-eql.sql')
    // A sibling carrying the SAME statement — the differential that proves the
    // sweep ran at all, rather than no-opping over the whole directory.
    const sibling = join(out, '0001_encrypt-email.sql')
    const unsafeAlter =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_text_search";\n'
    writeFileSync(sibling, unsafeAlter)
    spawnMock.mockImplementation(() => {
      fsWrite.real(generated, '')
      return { status: 0, stdout: '', stderr: '' }
    })
    // The install bundle contains no ALTER COLUMN of its own, so the skip would
    // have nothing to skip and this test would pass with `skip` removed. Append
    // one to whatever the command writes, so the skip is load-bearing.
    fsWrite.spy.mockImplementation(((path: string, data: unknown, ...rest) => {
      const content =
        typeof data === 'string' && data.includes('EQL v3 schema creation')
          ? `${data}\n${unsafeAlter}`
          : data
      return fsWrite.real(path, content as string, ...(rest as []))
    }) as typeof import('node:fs').writeFileSync)

    await eqlMigrationCommand({ drizzle: true, out })

    // Skipped: the statement survives verbatim in the generated migration...
    expect(readFileSync(generated, 'utf-8')).toContain(unsafeAlter)
    // ...while the identical statement in the sibling was rewritten.
    expect(readFileSync(sibling, 'utf-8')).not.toContain('SET DATA TYPE')
  })

  // When the sweep leaves near-misses it couldn't rewrite, the closing note
  // must warn the user the sweep didn't fully complete — otherwise they run
  // drizzle-kit migrate against un-swept, broken sibling SQL.
  it('warns at the closing note when the sweep leaves skipped statements', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    // A hand-authored SET DATA TYPE ... USING the strict matcher won't rewrite,
    // but the broad scan flags as a near-miss.
    const sibling = join(out, '0001_nearmiss.sql')
    writeFileSync(
      sibling,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;\n',
    )
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0002_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, out })

    // The near-miss statement is left untouched...
    expect(readFileSync(sibling, 'utf-8')).toContain('SET DATA TYPE')
    // ...and the closing note warns the sweep did not fully complete.
    const warned = clack.log.warn.mock.calls.map((c) => String(c[0]))
    expect(warned.some((msg) => msg.includes('did not fully complete'))).toBe(
      true,
    )
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

  // The `embedded` flag is asserted at the caller (install-eql.test.ts) as
  // *passed*; these pin what it *does* at the callee. All six suppression sites
  // hang off `options.embedded ?? false`, and none were exercised — flipping the
  // default or dropping an `if (!embedded)` guard would pass CI silently.
  it('emits the standalone banners by default (embedded unset)', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    spawnMock.mockImplementation(() => {
      fsWrite.real(join(out, '0000_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, out })

    expect(clack.intro).toHaveBeenCalled()
    expect(clack.outro).toHaveBeenCalledWith('Done!')
    expect(printNextSteps).toHaveBeenCalled()
  })

  it('suppresses intro/outro/next-steps when embedded, but still writes the SQL', async () => {
    // `stash init` renders its own summary + agent handoff; a second "what next"
    // block from here would compete with it. The migration itself is unchanged.
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    spawnMock.mockImplementation(() => {
      fsWrite.real(join(out, '0000_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, out, embedded: true })

    expect(clack.intro).not.toHaveBeenCalled()
    expect(clack.outro).not.toHaveBeenCalled()
    expect(printNextSteps).not.toHaveBeenCalled()
    // Presentational suppression only — the migration note itself still renders,
    // and the SQL is written to the located file.
    expect(clack.note).toHaveBeenCalledWith(expect.any(String), 'Next Steps')
    expect(readFileSync(join(out, '0000_install-eql.sql'), 'utf-8')).toContain(
      'EQL v3 schema creation',
    )
  })

  it('suppresses the abort outro when embedded but still exits 1', async () => {
    // `install-eql`'s catch depends on the CliExit propagating; embedded must
    // silence the outro banner without swallowing the failure.
    spawnMock.mockReturnValue({ status: 1, stdout: '', stderr: 'boom' })

    await expect(
      eqlMigrationCommand({
        drizzle: true,
        out: join(tmp, 'drizzle'),
        embedded: true,
      }),
    ).rejects.toBeInstanceOf(CliExit)

    expect(clack.outro).not.toHaveBeenCalled()
    expect(clack.log.error).toHaveBeenCalledWith('boom')
  })
})
