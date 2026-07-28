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
  // `step` is on the real clack `log`; omitting it made the sweep's
  // per-statement report throw and land in the command's catch block, so no
  // test ever saw the report. Keep it here.
  log: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    success: vi.fn(),
    step: vi.fn(),
  },
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

// Same seam on the async side. The ALTER-COLUMN sweep is the only thing in this
// command that writes through `node:fs/promises`, so a call-counting spy here
// makes a mid-sweep write failure deterministic — no chmod, which passes
// silently as root and varies by platform.
const fsWriteAsync = vi.hoisted(() => ({
  real: (() => {
    throw new Error(
      'fsWriteAsync.real not initialised: node:fs/promises mock factory did not run',
    )
  }) as typeof import('node:fs/promises').writeFile,
  spy: vi.fn(),
}))
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  fsWriteAsync.real = actual.writeFile
  return { ...actual, default: actual, writeFile: fsWriteAsync.spy }
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
  fsWriteAsync.spy.mockImplementation(fsWriteAsync.real)
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
    // The sweep is fail-closed: it rewrites a column only when the corpus
    // positively declares it (and it isn't already encrypted). A real drizzle
    // corpus carries this declaration in an earlier migration — supply it so
    // the fixture matches what the sweep actually requires.
    writeFileSync(
      join(out, '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
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
    // Fail-closed requires the corpus to positively declare the column before
    // the sweep will touch it — supply the declaration a real drizzle corpus
    // would carry, same as the sibling-rewrite test above.
    writeFileSync(
      join(out, '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    const generated = join(out, '0001_install-eql.sql')
    // A sibling carrying the SAME statement — the differential that proves the
    // sweep ran at all, rather than no-opping over the whole directory.
    const sibling = join(out, '0002_encrypt-email.sql')
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

  // A column the corpus never declares is fail-closed to `source-unknown`: left
  // on disk, and reported so the user goes and checks its type. This is the most
  // common skip on a real (e.g. squashed) corpus, and it renders through the
  // `p.log.step` path that a missing mock method used to make throw — so assert
  // the guidance text actually reaches the user, not just that a warning fired.
  it('reports source-unknown guidance for an undeclared column and warns at the close', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    // No CREATE TABLE / ADD COLUMN anywhere declares "users"."email".
    const sibling = join(out, '0001_encrypt-email.sql')
    const unsafeAlter =
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n'
    writeFileSync(sibling, unsafeAlter)
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0002_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, out })

    // Left exactly as written — a source-unknown statement is never rewritten.
    expect(readFileSync(sibling, 'utf-8')).toBe(unsafeAlter)
    // The per-statement report reached the user with the source-unknown
    // remediation (the whole point of the reason), not a crash into the catch.
    const stepped = clack.log.step.mock.calls.map((c) => String(c[0]))
    expect(stepped.some((msg) => msg.includes(sibling))).toBe(true)
    expect(
      stepped.some((msg) =>
        msg.includes("Check the column's current type in the database"),
      ),
    ).toBe(true)
    // And the closing note warns the sweep did not fully complete.
    const warned = clack.log.warn.mock.calls.map((c) => String(c[0]))
    expect(warned.some((msg) => msg.includes('did not fully complete'))).toBe(
      true,
    )
  })

  // The sweep writes one file at a time, so a failure part way through leaves
  // earlier files already rewritten — each holding a live `DROP COLUMN`. The
  // catch used to warn about the directory without naming them, so the user was
  // sent to "review the sibling migrations" with no idea which ones had already
  // become data-destroying (#786).
  it('reports completed, attempted, and skipped files when the sweep fails part way', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    writeFileSync(
      join(out, '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text, "name" text);\n',
    )
    const skipped = join(out, '0001_using-email.sql')
    writeFileSync(
      skipped,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;\n',
    )
    const rewritten = join(out, '0002_encrypt-email.sql')
    writeFileSync(
      rewritten,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )
    const attempted = join(out, '0003_encrypt-name.sql')
    writeFileSync(
      attempted,
      'ALTER TABLE "users" ALTER COLUMN "name" SET DATA TYPE eql_v3_text_search;\n',
    )
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0004_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })
    // The generated migration is `skip`ped and 0001 is only flagged, so the
    // writes are #1 for 0002 and #2 — the rejected one — for 0003.
    let asyncWrites = 0
    fsWriteAsync.spy.mockImplementation(
      async (
        ...args: Parameters<typeof import('node:fs/promises').writeFile>
      ): Promise<void> => {
        asyncWrites += 1
        if (asyncWrites === 2) {
          await fsWriteAsync.real(args[0], '', 'utf-8')
          throw new Error('ENOSPC: no space left on device')
        }
        await fsWriteAsync.real(...args)
      },
    )

    await eqlMigrationCommand({ drizzle: true, out })

    // The first file really was rewritten and is sitting there destructive.
    expect(readFileSync(rewritten, 'utf-8')).toContain('DROP COLUMN')
    // The rejected write really did mutate its destination too.
    expect(readFileSync(attempted, 'utf-8')).toBe('')
    // Both possible rewrites and the earlier near-miss must survive the catch.
    const stepped = clack.log.step.mock.calls.map((c) => String(c[0]))
    expect(stepped.some((msg) => msg.includes(rewritten))).toBe(true)
    expect(stepped.some((msg) => msg.includes(attempted))).toBe(true)
    expect(stepped.some((msg) => msg.includes(skipped))).toBe(true)
    const infos = clack.log.info.mock.calls.map((c) => String(c[0]))
    expect(infos.some((msg) => msg.includes('Rewrote 2 migration file'))).toBe(
      true,
    )
    // And the failure itself is still reported, with the closing warning.
    const warned = clack.log.warn.mock.calls.map((c) => String(c[0]))
    expect(warned.some((msg) => msg.includes('ENOSPC'))).toBe(true)
    expect(
      warned.some((msg) => msg.includes('1 ALTER-to-encrypted statement')),
    ).toBe(true)
    expect(warned.some((msg) => msg.includes('did not fully complete'))).toBe(
      true,
    )

    // Put the potentially damaged paths and destructive context before the
    // write failure, then close with the incomplete-sweep warning.
    const rewriteInfoIndex = infos.findIndex((msg) =>
      msg.includes('Rewrote 2 migration file'),
    )
    const rewrittenStepIndex = stepped.findIndex((msg) =>
      msg.includes(rewritten),
    )
    const attemptedStepIndex = stepped.findIndex((msg) =>
      msg.includes(attempted),
    )
    const failureWarnIndex = warned.findIndex((msg) => msg.includes('ENOSPC'))
    const closingWarnIndex = warned.findIndex((msg) =>
      msg.includes('did not fully complete'),
    )
    const failureOrder =
      clack.log.warn.mock.invocationCallOrder[failureWarnIndex]
    expect(
      clack.log.info.mock.invocationCallOrder[rewriteInfoIndex],
    ).toBeLessThan(failureOrder)
    expect(
      clack.log.step.mock.invocationCallOrder[rewrittenStepIndex],
    ).toBeLessThan(failureOrder)
    expect(
      clack.log.step.mock.invocationCallOrder[attemptedStepIndex],
    ).toBeLessThan(failureOrder)
    expect(failureOrder).toBeLessThan(
      clack.log.warn.mock.invocationCallOrder[closingWarnIndex],
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
