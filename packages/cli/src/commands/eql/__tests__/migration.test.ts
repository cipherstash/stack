import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'
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

// Pin the detected package manager so the argv assertion below can name the
// exact runner prefix. Detection walks the real filesystem, so without this the
// expected argv would have to be computed from `execArgv` — which makes the
// assertion tautological and unable to catch a regression back to the
// download-and-run (`dlx`) form. Everything else in `utils.js` stays real.
vi.mock('@/commands/init/utils.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/commands/init/utils.js')>()),
  detectPackageManager: () => 'pnpm',
}))

// The sweep stays REAL by default — every other sweep test drives it through
// actual SQL on disk. The spy exists so the "sweep threw" branch can be reached
// with a throw the sweep itself never produces (a bare string, `null`), which is
// the case the partial-result reporting has to survive without masking.
const rewriteMock = vi.hoisted(() => ({
  real: (() => {
    throw new Error(
      'rewriteMock.real not initialised: rewrite-migrations mock factory did not run',
    )
  }) as typeof import('../../db/rewrite-migrations.js').rewriteEncryptedAlterColumns,
  spy: vi.fn(),
}))
vi.mock('../../db/rewrite-migrations.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../db/rewrite-migrations.js')>()
  rewriteMock.real = actual.rewriteEncryptedAlterColumns
  return { ...actual, rewriteEncryptedAlterColumns: rewriteMock.spy }
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
  rewriteMock.spy.mockImplementation(rewriteMock.real)
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
    ['--prisma', { prisma: true }, () => messages.eql.migrationPrismaNotNeeded],
  ])('exits 1 with an actionable message for %s', async (_label, opts, msg) => {
    await expect(eqlMigrationCommand(opts)).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(msg())
    expect(spawnMock).not.toHaveBeenCalled()
  })

  /**
   * `--prisma --supabase` is not caught by the `drizzle && prisma`
   * mutual-exclusion check — the only thing standing between it and the
   * Supabase emitter is BRANCH ORDERING: the `--prisma` rejection sits above
   * the `--supabase` dispatch, so the command exits before
   * `generateSupabaseEqlMigration` runs. That guard is invisible in the source
   * and a future reorder would silently route this invocation into the
   * emitter, so pin it here.
   *
   * `expect(spawnMock).not.toHaveBeenCalled()` (the assertion the sibling cases
   * use) cannot detect that regression: the Supabase emitter never spawns
   * anything, it writes files directly. So stub `process.cwd` at a fresh
   * tmpdir the way the `--out` suite below does and assert the directory is
   * untouched — the emitter would create `supabase/migrations/` under it.
   */
  it('rejects `--prisma --supabase` before the Supabase emitter writes anything', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'stash-eql-prisma-supabase-'))
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(tmp)
    try {
      await expect(
        eqlMigrationCommand({ prisma: true, supabase: true }),
      ).rejects.toBeInstanceOf(CliExit)

      expect(clack.log.error).toHaveBeenCalledWith(
        messages.eql.migrationPrismaNotNeeded,
      )
      // Nothing written, nothing created, no emitter side effects.
      expect(readdirSync(tmp)).toHaveLength(0)
      expect(existsSync(join(tmp, 'supabase', 'migrations'))).toBe(false)
      expect(clack.log.success).not.toHaveBeenCalled()
      expect(spawnMock).not.toHaveBeenCalled()
    } finally {
      cwd.mockRestore()
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('treats `--drizzle --supabase` as one target, not two', async () => {
    // `--supabase` is the grants modifier here, not a second target. Counting
    // it as one would reject the documented Supabase-hosted-Drizzle invocation.
    const tmp = mkdtempSync(join(tmpdir(), 'stash-eql-targets-'))
    try {
      await eqlMigrationCommand({
        drizzle: true,
        supabase: true,
        out: tmp,
        dryRun: true,
      })
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
    expect(clack.log.error).not.toHaveBeenCalled()
  })
})

/**
 * The Supabase emitter. No drizzle-kit, no journal, no ALTER COLUMN sweep —
 * just the install SQL written where `supabase db reset` will replay it.
 */
describe('eqlMigrationCommand — Supabase', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'stash-eql-supabase-'))
  })
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('writes the install into --out and never spawns drizzle-kit', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp })

    const written = readdirSync(tmp)
    expect(written).toHaveLength(1)
    expect(written[0]).toMatch(/^\d{14}_cipherstash_eql\.sql$/)
    expect(spawnMock).not.toHaveBeenCalled()
  })

  it('always includes the role grants — a Supabase file is applied by Supabase', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp })

    const body = readFileSync(join(tmp, readdirSync(tmp)[0]), 'utf-8')
    expect(body).toContain(
      'GRANT USAGE ON SCHEMA eql_v3 TO anon, authenticated, service_role',
    )
    expect(body).toContain(
      'GRANT USAGE ON SCHEMA eql_v3_internal TO anon, authenticated, service_role',
    )
    // One reset provisions everything `stash encrypt` needs.
    expect(body).toContain('cs_migrations')
  })

  it('dry run previews the directory and writes nothing', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp, dryRun: true })

    expect(readdirSync(tmp)).toHaveLength(0)
    expect(clack.note).toHaveBeenCalledWith(
      expect.stringContaining(tmp),
      'Dry Run',
    )
  })

  it('dry run predicts the refusal when an install migration already exists', async () => {
    // Regression: the preview always claimed it "would write" a new file, even
    // in a directory where the real run exits 1. A dry run that predicts the
    // wrong outcome is worse than no dry run.
    writeFileSync(join(tmp, '20260101000000_cipherstash_eql.sql'), '')

    await eqlMigrationCommand({ supabase: true, out: tmp, dryRun: true })

    const [note] = vi.mocked(clack.note).mock.calls.at(-1) ?? []
    expect(note).toContain('20260101000000_cipherstash_eql.sql')
    expect(note).toMatch(/--force/)
    expect(note).not.toMatch(/Would write/i)
  })

  it('dry run predicts the in-place overwrite under --force', async () => {
    writeFileSync(join(tmp, '20260101000000_cipherstash_eql.sql'), '')

    await eqlMigrationCommand({
      supabase: true,
      out: tmp,
      dryRun: true,
      force: true,
    })

    const [note] = vi.mocked(clack.note).mock.calls.at(-1) ?? []
    expect(note).toContain('20260101000000_cipherstash_eql.sql')
    expect(note).toMatch(/replace/i)
  })

  it('exits 1 rather than adding a second install migration', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp })
    await expect(
      eqlMigrationCommand({ supabase: true, out: tmp }),
    ).rejects.toBeInstanceOf(CliExit)

    expect(readdirSync(tmp)).toHaveLength(1)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('already exists'),
    )
  })

  it('replaces in place under --force and warns about applied databases', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp })
    const original = readdirSync(tmp)[0]

    await eqlMigrationCommand({ supabase: true, out: tmp, force: true })

    expect(readdirSync(tmp)).toEqual([original])
    // The warning must name the hazard, not just note the replacement: a
    // database that already ran the old file is the whole point of saying
    // anything.
    const [warning] = vi.mocked(clack.log.warn).mock.calls.at(-1) ?? []
    expect(warning).toMatch(/already applied/)
  })

  /**
   * The re-apply guidance after an in-place overwrite. `supabase db push` does
   * NOT re-apply a rewritten file: `FindPendingMigrations`
   * (`pkg/migration/apply.go`) computes the pending set positionally —
   * `pending := localMigrations[len(remoteMigrations):]` — with no content hash
   * and no statement diff, unlike seed files, which carry a `Hash`/`Dirty` pair
   * and do re-run on change. Equal counts mean an empty pending set, so
   * `push.Run` prints "Remote database is up to date." and applies nothing. A
   * user following "re-apply with db push" would believe the remote was updated
   * when it was not.
   */
  describe('--force re-apply guidance', () => {
    const replaceInPlace = async () => {
      await eqlMigrationCommand({ supabase: true, out: tmp })
      const version = readdirSync(tmp)[0].slice(0, 14)
      vi.clearAllMocks()
      await eqlMigrationCommand({ supabase: true, out: tmp, force: true })
      return version
    }
    const lastWarning = () =>
      String(vi.mocked(clack.log.warn).mock.calls.at(-1)?.[0] ?? '')
    const lastNote = () =>
      String(vi.mocked(clack.note).mock.calls.at(-1)?.[0] ?? '')

    it('says db push will not re-apply the replaced file', async () => {
      await replaceInPlace()

      expect(lastWarning()).toMatch(/`supabase db push` will not re-apply/)
      // The reason, not just the verdict — otherwise it reads as a bug report.
      expect(lastWarning()).toMatch(/by version, not by content/)
    })

    it('names the cascade hazard of re-applying to a live database', async () => {
      // The bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE;` /
      // `DROP SCHEMA IF EXISTS eql_v3_internal CASCADE;`, so a re-apply takes
      // every dependent index, constraint, and RLS policy with it. Free on a
      // fresh `db reset`; not on a populated remote.
      await replaceInPlace()

      expect(lastWarning()).toContain('DROP SCHEMA IF EXISTS eql_v3 CASCADE')
      expect(lastWarning()).toMatch(/RLS polic/)
    })

    it('gives the repair-then-push remote recipe, with --include-all as a conditional', async () => {
      const version = await replaceInPlace()

      // `migration repair --status reverted` clears the ledger row (tracking
      // table only — it applies no SQL), which puts the version back in the
      // pending set.
      expect(lastNote()).toContain(
        `supabase migration repair --status reverted ${version}`,
      )
      expect(lastNote()).toContain('supabase db reset')

      // The plain push is the instruction; --include-all is the fallback for
      // when it aborts. Reverting the NEWEST version leaves it at the tail of
      // remote history, where a plain push applies it — only a version with
      // migrations above it is the gap that trips ErrMissingRemote. Pinned live
      // in supabase-push.live.test.ts against supabase/cli 2.111.0; an earlier
      // revision of this message demanded the flag unconditionally, which
      // applies every out-of-order migration the user has.
      const note = lastNote()
      expect(note).toContain('supabase db push\n')
      expect(note).toMatch(/re-run it as `supabase db push --include-all`/)
      expect(note).toMatch(/only when the push tells you to/i)
    })

    it('keeps the plain apply note when nothing was replaced', async () => {
      await eqlMigrationCommand({ supabase: true, out: tmp })

      expect(lastNote()).toContain('supabase db push')
      expect(lastNote()).not.toContain('migration repair')
    })
  })

  /**
   * Brownfield ordering (#613's second act). A user who ran `stash eql install`
   * directly, then added migrations creating encrypted columns, then found this
   * command, gets an install stamped with today's date — which sorts AFTER those
   * migrations. `supabase db reset` replays in version order with no dependency
   * awareness, so they run first, reference a domain that does not exist yet,
   * and the reset fails.
   *
   * Detection and a warning, deliberately not a fix: back-dating the file or
   * renaming theirs are both the user's call.
   */
  describe('EQL-dependent migrations that sort before the install', () => {
    const warnings = () =>
      clack.log.warn.mock.calls.map((c) => String(c[0])).join('\n')
    /** Distinctive enough to assert absence on. */
    const FRAGMENT = 'replays the directory in version order'
    const EARLIER = '20260101000000_add_email_encrypted.sql'
    const ENCRYPTED_COLUMN_SQL =
      'ALTER TABLE users ADD COLUMN email_encrypted public.eql_v3_text_search;\n'

    it('warns, naming the file and the consequence', async () => {
      writeFileSync(join(tmp, EARLIER), ENCRYPTED_COLUMN_SQL)

      await eqlMigrationCommand({ supabase: true, out: tmp })

      expect(clack.log.warn).toHaveBeenCalledWith(
        messages.eql.migrationSupabaseEqlBeforeInstall(tmp, [EARLIER]),
      )
      expect(warnings()).toContain(EARLIER)
      expect(warnings()).toContain('supabase db reset')
      // The remedy, including the flag a back-dated push needs.
      expect(warnings()).toContain('--include-all')
    })

    it('splits the remote remedy by whether EQL is already installed there', async () => {
      // The brownfield case this warning fires on is, by definition, a project
      // that ran `stash eql install` directly — so the remote usually HAS EQL
      // and is missing only the ledger row. Sending that user to `db push
      // --include-all` re-runs a bundle opening with `DROP SCHEMA IF EXISTS
      // eql_v3 CASCADE`, taking every dependent index, constraint, and RLS
      // policy with it. The ledger-only repair must be the named default, with
      // --include-all kept for a remote that genuinely lacks the SQL.
      writeFileSync(join(tmp, EARLIER), ENCRYPTED_COLUMN_SQL)

      await eqlMigrationCommand({ supabase: true, out: tmp })

      expect(warnings()).toContain('supabase migration repair --status applied')
      expect(warnings()).toContain('DROP SCHEMA IF EXISTS eql_v3 CASCADE')
      expect(warnings()).toMatch(/RLS polic/)
      // Both halves present, and the destructive one is the conditional.
      expect(warnings()).toContain('--include-all')
    })

    it('makes the remote state a check to run, ahead of the ledger repair', async () => {
      // Which half of that split applies turns on a fact the user is otherwise
      // never asked to establish. Marking a version applied is the one remedy
      // here with no self-correcting failure: get it wrong and the ledger
      // claims SQL ran that never did, so no later push installs EQL and the
      // first `eql_v3` reference fails with nothing pointing at the cause. The
      // check therefore has to be a printed command, above the repair.
      writeFileSync(join(tmp, EARLIER), ENCRYPTED_COLUMN_SQL)

      await eqlMigrationCommand({ supabase: true, out: tmp })

      const warning = warnings()
      expect(warning).toContain(
        'psql "$REMOTE_DATABASE_URL" -Atc "select eql_v3.version()"',
      )
      expect(warning.indexOf('select eql_v3.version()')).toBeLessThan(
        warning.indexOf('supabase migration repair --status applied'),
      )
    })

    it('checks a bundle-final object, which a half-applied install lacks', async () => {
      // `eql_v3.version()` is created by the bundle's closing statements, so it
      // is present only if the whole install ran. A probe for the `eql_v3`
      // schema would pass on an install that aborted halfway — the schema is
      // created by the bundle's opening statements — and "partially installed"
      // read as "installed" is exactly the state the ledger row must not be
      // written for.
      writeFileSync(join(tmp, EARLIER), ENCRYPTED_COLUMN_SQL)

      await eqlMigrationCommand({ supabase: true, out: tmp })

      expect(warnings()).toMatch(/last statements of the bundle/)
      // The unrecoverable direction is named, not left as an inference.
      expect(warnings()).toMatch(/[Nn]ever mark it applied/)
    })

    it('stays quiet when the EQL-referencing migration sorts after the install', async () => {
      writeFileSync(
        join(tmp, '20990101000000_add_email_encrypted.sql'),
        ENCRYPTED_COLUMN_SQL,
      )

      await eqlMigrationCommand({ supabase: true, out: tmp })

      expect(warnings()).not.toContain(FRAGMENT)
    })

    it('never warns for an earlier migration that does not reference EQL', async () => {
      writeFileSync(
        join(tmp, '20260101000000_users.sql'),
        'CREATE TABLE users (id uuid PRIMARY KEY, email text);\n',
      )

      await eqlMigrationCommand({ supabase: true, out: tmp })

      expect(warnings()).not.toContain(FRAGMENT)
    })

    it('warns on a dry run, which is where the prediction is still free', async () => {
      writeFileSync(join(tmp, EARLIER), ENCRYPTED_COLUMN_SQL)

      await eqlMigrationCommand({ supabase: true, out: tmp, dryRun: true })

      expect(warnings()).toContain(FRAGMENT)
      // Nothing written — the user's own migration is all that is there.
      expect(readdirSync(tmp)).toEqual([EARLIER])
    })

    it('stays quiet for an empty migrations directory', async () => {
      await eqlMigrationCommand({ supabase: true, out: tmp })

      expect(warnings()).not.toContain(FRAGMENT)
    })

    it('stays quiet for a migrations directory that does not exist yet', async () => {
      await eqlMigrationCommand({ supabase: true, out: join(tmp, 'nope') })

      expect(warnings()).not.toContain(FRAGMENT)
    })

    it('warns above the dry-run branch, inside the command frame', async () => {
      // Same placement discipline as the --out warning: after the intro (so
      // clack renders it inside the frame) and before the dry-run return.
      writeFileSync(join(tmp, EARLIER), ENCRYPTED_COLUMN_SQL)

      await eqlMigrationCommand({ supabase: true, out: tmp, dryRun: true })

      const introAt = vi.mocked(clack.intro).mock.invocationCallOrder[0]
      const warnAt = clack.log.warn.mock.calls.findIndex((c) =>
        String(c[0]).includes(FRAGMENT),
      )
      expect(warnAt).toBeGreaterThanOrEqual(0)
      expect(clack.log.warn.mock.invocationCallOrder[warnAt]).toBeGreaterThan(
        introAt,
      )
    })
  })

  it('warns that --name is ignored rather than silently dropping it', async () => {
    // The filename is load-bearing: duplicate detection matches the
    // `_cipherstash_eql.sql` suffix, so --name cannot be honoured here. Saying
    // nothing would leave the user believing they had renamed it.
    await eqlMigrationCommand({ supabase: true, out: tmp, name: 'my-install' })

    expect(clack.log.warn).toHaveBeenCalledWith(
      messages.eql.migrationNameDrizzleOnly,
    )
    expect(readdirSync(tmp)[0]).toMatch(/^\d{14}_cipherstash_eql\.sql$/)
  })

  it('warns about --name inside the command frame, not above it', async () => {
    // clack renders log lines into the frame the intro opens. Warning first
    // put the line above the banner, detached from the command it belongs to.
    await eqlMigrationCommand({ supabase: true, out: tmp, name: 'my-install' })

    const introAt = vi.mocked(clack.intro).mock.invocationCallOrder[0]
    const warnAt = vi.mocked(clack.log.warn).mock.invocationCallOrder[0]
    expect(warnAt).toBeGreaterThan(introAt)
  })

  it('still warns about --name on a dry run, which also ignores it', async () => {
    await eqlMigrationCommand({
      supabase: true,
      out: tmp,
      name: 'my-install',
      dryRun: true,
    })

    expect(clack.log.warn).toHaveBeenCalledWith(
      messages.eql.migrationNameDrizzleOnly,
    )
  })

  it('stays quiet about --name when it was not passed', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp })

    expect(clack.log.warn).not.toHaveBeenCalledWith(
      messages.eql.migrationNameDrizzleOnly,
    )
  })

  it('emits the standalone banners by default', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp })

    expect(clack.intro).toHaveBeenCalledWith('CipherStash EQL migration')
    expect(clack.outro).toHaveBeenCalledWith('Done!')
    expect(printNextSteps).toHaveBeenCalled()
  })

  it('suppresses intro/outro/next-steps when embedded, but still writes', async () => {
    // `stash init` renders its own summary and agent handoff; two competing
    // "what next" blocks is the bug this flag exists to prevent.
    await eqlMigrationCommand({ supabase: true, out: tmp, embedded: true })

    expect(readdirSync(tmp)).toHaveLength(1)
    expect(clack.intro).not.toHaveBeenCalled()
    expect(clack.outro).not.toHaveBeenCalled()
    expect(printNextSteps).not.toHaveBeenCalled()
  })

  it('suppresses the abort outro when embedded but still exits 1', async () => {
    await eqlMigrationCommand({ supabase: true, out: tmp })
    vi.clearAllMocks()

    await expect(
      eqlMigrationCommand({ supabase: true, out: tmp, embedded: true }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.outro).not.toHaveBeenCalled()
  })

  /**
   * `--out` on a bare `--supabase` can silently reintroduce #613, the very bug
   * this emitter exists to fix. The Supabase CLI's migrations directory is not
   * configurable — `db reset` and `db push` read `<project>/supabase/migrations`
   * and nothing else — so a file written anywhere else is EQL missing from the
   * replayed directory all over again, just relocated. The flag stays (a user
   * may have their own apply step) but must not be silent.
   *
   * `process.cwd` is stubbed rather than `process.chdir`-ing, because the
   * default arm has to write a real file and doing that relative to the repo
   * root would litter it.
   */
  describe('--out outside supabase/migrations', () => {
    const warnings = () =>
      clack.log.warn.mock.calls.map((c) => String(c[0])).join('\n')

    // Restored here rather than by a global `restoreAllMocks`, which would also
    // tear down the module-level `vi.fn()` mocks this file depends on.
    let restoreCwd: (() => void) | undefined
    const stubCwd = (dir: string) => {
      const spy = vi.spyOn(process, 'cwd').mockReturnValue(dir)
      restoreCwd = () => spy.mockRestore()
    }
    afterEach(() => {
      restoreCwd?.()
      restoreCwd = undefined
    })

    it('warns for a relative --out that is not the default', async () => {
      stubCwd(tmp)

      await eqlMigrationCommand({ supabase: true, out: 'db/migrations' })

      expect(clack.log.warn).toHaveBeenCalledWith(
        messages.eql.migrationSupabaseOutNotReplayed(
          join(tmp, 'db', 'migrations'),
        ),
      )
      // The consequence, not just the deviation: a user who reads "non-standard
      // directory" and shrugs is exactly the user this warning is for.
      expect(warnings()).toContain('supabase db reset')
    })

    it('warns for an absolute --out that is not the default', async () => {
      stubCwd(tmp)
      const out = join(tmp, 'elsewhere')

      await eqlMigrationCommand({ supabase: true, out })

      expect(clack.log.warn).toHaveBeenCalledWith(
        messages.eql.migrationSupabaseOutNotReplayed(out),
      )
    })

    it('stays quiet when --out is omitted', async () => {
      stubCwd(tmp)

      await eqlMigrationCommand({ supabase: true })

      expect(readdirSync(join(tmp, 'supabase', 'migrations'))).toHaveLength(1)
      expect(warnings()).not.toContain('--out points at')
    })

    it('stays quiet when --out resolves to exactly the default', async () => {
      // Same directory, spelled the long way. Comparing the raw string would
      // fire here — the check has to compare resolved paths.
      stubCwd(tmp)

      await eqlMigrationCommand({ supabase: true, out: 'supabase/migrations' })

      expect(readdirSync(join(tmp, 'supabase', 'migrations'))).toHaveLength(1)
      expect(warnings()).not.toContain('--out points at')
    })

    it('stays quiet for an absolute --out that normalises to the default', async () => {
      // An absolute --out is taken verbatim by `detectSupabaseProject`, so the
      // trailing separator a user typed (or a shell completed) survives into the
      // comparison. Raw string equality would warn about the directory it is
      // already writing to.
      stubCwd(tmp)

      await eqlMigrationCommand({
        supabase: true,
        out: `${join(tmp, 'supabase', 'migrations')}${sep}`,
      })

      expect(warnings()).not.toContain('--out points at')
    })

    it('warns on a dry run, which is where the prediction matters most', async () => {
      // A dry run exists to tell you what the real run will do. Withholding the
      // one thing that makes the real run pointless would defeat it.
      stubCwd(tmp)

      await eqlMigrationCommand({
        supabase: true,
        out: 'db/migrations',
        dryRun: true,
      })

      expect(clack.log.warn).toHaveBeenCalledWith(
        messages.eql.migrationSupabaseOutNotReplayed(
          join(tmp, 'db', 'migrations'),
        ),
      )
    })

    it('leaves the replacement warning last so --force still reads correctly', async () => {
      // Both fire on a forced re-run into a custom directory. The out warning is
      // an up-front flag advisory; the replacement warning is the outcome, and
      // has to stay adjacent to the success line it qualifies.
      stubCwd(tmp)
      await eqlMigrationCommand({ supabase: true, out: 'db/migrations' })
      // `clearAllMocks` only clears recorded calls; the cwd stub's return value
      // survives, and re-stubbing would nest a second spy the restore can't undo.
      vi.clearAllMocks()

      await eqlMigrationCommand({
        supabase: true,
        out: 'db/migrations',
        force: true,
      })

      const [last] = vi.mocked(clack.log.warn).mock.calls.at(-1) ?? []
      expect(last).toMatch(/already applied/)
    })

    it('never warns on the --drizzle --supabase grants path', async () => {
      // There `--supabase` is the grants modifier and `--out` is a drizzle-kit
      // output directory, which has nothing to do with supabase/migrations.
      // Warning would be nonsense advice on the documented invocation.
      const out = join(tmp, 'drizzle')

      await eqlMigrationCommand({
        drizzle: true,
        supabase: true,
        out,
        dryRun: true,
      })

      expect(warnings()).not.toContain('--out points at')
    })
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

  it.each([
    ['command substitution', 'a$(whoami)'],
    ['backticks', 'a`id`'],
    ['a path separator', '../escape'],
    // `''` is not nullish, so it slips past `options.name ?? DEFAULT` and hits
    // the regex, where `+` rejects it — `--name ''` aborts, it does NOT fall
    // back to `install-eql`. The one input where "empty" and "absent" diverge.
    ['an empty string', ''],
  ])('rejects %s in --name', async (_label, name) => {
    await expect(
      eqlMigrationCommand({ drizzle: true, name, out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(spawnMock).not.toHaveBeenCalled()
  })

  // Ordering invariant: name validation sits ABOVE the dry-run preview, so a
  // bad name aborts before anything is rendered. Move the validation below the
  // preview and an unvalidated name ships into the note — with no other test
  // combining the two, that refactor would pass CI.
  it('rejects an unsafe name in a dry run too (validation precedes the preview)', async () => {
    await expect(
      eqlMigrationCommand({ drizzle: true, name: 'x; ls', dryRun: true }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.note).not.toHaveBeenCalled()
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

  it('includes --out in the dry-run preview', async () => {
    const out = join(tmp, 'custom-out')
    await eqlMigrationCommand({ drizzle: true, dryRun: true, out })
    expect(spawnMock).not.toHaveBeenCalled()
    expect(clack.note).toHaveBeenCalledWith(
      expect.stringContaining(`--out=${out}`),
      'Dry Run',
    )
  })

  // Widest blast radius of the flag handling: because `--out` is ALWAYS
  // appended to drizzle-kit's argv, a flag-less invocation silently overrides
  // the project's drizzle.config.ts `out` with `<cwd>/drizzle`. The dry-run
  // preview reaches that arm without spawning or touching the filesystem.
  it('defaults --out to an absolute drizzle/ when the flag is omitted', async () => {
    await eqlMigrationCommand({ drizzle: true, dryRun: true })
    expect(clack.note).toHaveBeenCalledWith(
      expect.stringContaining(`--out=${resolve('drizzle')}`),
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

    expect(spawnMock).toHaveBeenCalledTimes(1)
    const [command, argv] = spawnMock.mock.calls[0]
    // The whole argv, exactly — not `toContain` checks, which would still pass
    // if the runner prefix (`exec`) were dropped and drizzle-kit ran under the
    // wrong resolver. Three things at once: name and out are discrete inert
    // tokens in an array, never interpolated into a shell string; `--out` is
    // actually passed, so drizzle-kit writes where step 2 then looks; and the
    // project-local `exec` form (not `dlx`) is asserted, so a regression back to
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
    expect(written).toContain('EQL v3 schema creation')
    expect(written).toContain('cs_migrations')
  })

  // drizzle-kit emits an un-runnable in-place `ALTER COLUMN ... SET DATA TYPE`
  // when a plaintext column is changed to an encrypted one. `eql install
  // --drizzle` has always swept the out directory for these; the v3
  // migration-first path must do the same, but the rewrite is now add-only and
  // fails closed when it cannot prove the source column.
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
      'ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    )
    expect(rewritten).not.toContain('SET DATA TYPE')
    // The add-only invariant, at the COMMAND level. Both rewriter unit suites
    // pin it too, but only this asserts what the command actually leaves on
    // disk — the wiring between them is where a regression would hide.
    expect(rewritten).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
    // The success line is the user's only signal that the sweep did anything.
    const info = clack.log.info.mock.calls.map((c) => String(c[0]))
    expect(info.some((msg) => msg.includes('Rewrote 1 migration file'))).toBe(
      true,
    )
  })

  /**
   * #836, item 2. A successful sweep used to be silent about the state it left
   * behind: the database gains `email_encrypted`, while schema.ts and the
   * drizzle-kit snapshot both still declare `email` as the domain and know
   * nothing about the twin. `drizzle-kit generate` cannot surface that — it
   * diffs schema.ts against the snapshot and those two still agree — so the
   * command has to say it.
   */
  it('warns that schema.ts and the snapshot diverged after staging a twin', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    writeFileSync(
      join(out, '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    writeFileSync(
      join(out, '0001_encrypt-email.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_text_search";\n',
    )
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0002_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, out })

    const warnings = clack.log.warn.mock.calls
      .map((c) => String(c[0]))
      .join('\n')
    // Named precisely, not a generic "review your schema".
    expect(warnings).toContain('users:')
    expect(warnings).toContain('"email_encrypted" eql_v3_text_search')
    // The three things the user cannot discover from the tooling.
    expect(warnings).toContain('drizzle-kit generate` will NOT warn you')
    expect(warnings).toContain('column already exists')
    expect(warnings).toContain('SUCCEED')
  })

  // Warning, not a failure: the swept SQL is valid and additive, so the command
  // must still succeed and still print its next-steps note.
  it('does not exit non-zero merely because a twin was staged', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    writeFileSync(
      join(out, '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    writeFileSync(
      join(out, '0001_encrypt-email.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_text_search";\n',
    )
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0002_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await expect(
      eqlMigrationCommand({ drizzle: true, out }),
    ).resolves.toBeUndefined()

    expect(clack.log.error).not.toHaveBeenCalled()
    expect(clack.log.success).toHaveBeenCalled()
  })

  // No rewrite means nothing diverged, so the notice must not fire — it would
  // send the user editing a schema that is already consistent.
  it('does not warn about reconciliation when nothing was staged', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    writeFileSync(
      join(out, '0000_unrelated.sql'),
      'CREATE TABLE "widgets" ("id" integer);\n',
    )
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0001_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })

    await eqlMigrationCommand({ drizzle: true, out })

    const warnings = clack.log.warn.mock.calls
      .map((c) => String(c[0]))
      .join('\n')
    expect(warnings).not.toContain('drizzle-kit generate` will NOT warn you')
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

    await expect(
      eqlMigrationCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)

    // The near-miss statement is left untouched...
    expect(readFileSync(sibling, 'utf-8')).toContain('SET DATA TYPE')
    // ...and the command fails closed with the sweep error.
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('unsafe or unverified SQL'),
    )
    expect(clack.outro).toHaveBeenCalledWith('Migration aborted.')
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

    await expect(
      eqlMigrationCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)

    // Left exactly as written — a source-unknown statement is never rewritten.
    expect(readFileSync(sibling, 'utf-8')).toBe(unsafeAlter)
    // The per-statement report reached the user with the source-unknown
    // remediation (the whole point of the reason), and the command failed
    // closed instead of continuing.
    const stepped = clack.log.step.mock.calls.map((c) => String(c[0]))
    expect(stepped.some((msg) => msg.includes(sibling))).toBe(true)
    expect(
      stepped.some((msg) =>
        msg.includes("Check the column's current type in the database"),
      ),
    ).toBe(true)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('unsafe or unverified SQL'),
    )
  })

  // The catch reads `rewritten` / `skipped` off the thrown value to report the
  // work a partial sweep did complete (#786). A throw that is not an object —
  // or not one carrying those arrays — must fall through to the plain "could
  // not sweep" message and still fail closed, not crash on a property read.
  it.each([
    null,
    undefined,
    'rewrite failed',
  ])('handles a non-object sweep failure without masking it: %s', async (failure) => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0000_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })
    rewriteMock.spy.mockRejectedValueOnce(failure)

    await expect(
      eqlMigrationCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not sweep'),
    )
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('unsafe or unverified SQL'),
    )
  })

  /**
   * A sweep that threw PART WAY through has already written staged twins to
   * disk, so the same three-way divergence exists for them and the
   * reconciliation notice still has to fire. The command aborts either way —
   * this pins that aborting does not swallow the guidance for work that did
   * land.
   */
  it('reports staged twins from a sweep that threw part way through', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    spawnMock.mockImplementation(() => {
      writeFileSync(join(out, '0000_install-eql.sql'), '')
      return { status: 0, stdout: '', stderr: '' }
    })
    const partial = Object.assign(new Error('EISDIR'), {
      rewritten: [join(out, '0001_encrypt.sql')],
      skipped: [],
      staged: [
        {
          file: join(out, '0001_encrypt.sql'),
          table: 'users',
          column: 'email',
          encryptedColumn: 'email_encrypted',
          domain: 'eql_v3_text_search',
        },
      ],
    })
    rewriteMock.spy.mockRejectedValueOnce(partial)

    await expect(
      eqlMigrationCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)

    const warnings = clack.log.warn.mock.calls
      .map((c) => String(c[0]))
      .join('\n')
    expect(warnings).toContain('"email_encrypted" eql_v3_text_search')
    expect(warnings).toContain('drizzle-kit generate` will NOT warn you')
    expect(warnings).toContain('column already exists')
  })

  it('aborts (exit 1) when drizzle-kit exits non-zero', async () => {
    spawnMock.mockReturnValue({ status: 1, stdout: '', stderr: 'boom' })
    await expect(
      eqlMigrationCommand({ drizzle: true, out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith('boom')
  })

  it('reports the spawn error when drizzle-kit cannot be launched', async () => {
    // spawnSync's ENOENT shape: null status, no captured stderr, `error` set.
    // `result.stderr?.trim()` is undefined, so the message falls through to the
    // second arm (`result.error?.message`) — the realistic "drizzle-kit isn't
    // installed" case. If the `?.` on stderr were dropped, this shape would
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
      eqlMigrationCommand({ drizzle: true, out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith('spawnSync pnpm ENOENT')
    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining('Make sure drizzle-kit is installed'),
    )
  })

  it('falls back to the exit status when there is no stderr or spawn error', async () => {
    // Third arm of the fallback chain: non-zero status, empty stderr, no
    // `error`. The user still gets a message instead of a blank error line.
    spawnMock.mockReturnValue({ status: 2, stdout: '', stderr: '' })

    await expect(
      eqlMigrationCommand({ drizzle: true, out: join(tmp, 'drizzle') }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(
      'drizzle-kit exited with status 2.',
    )
  })

  it('points at --out when the generated migration is not where we looked', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    // drizzle-kit "succeeds" but wrote to its own drizzle.config.ts `out`, not
    // ours, so step 2 finds nothing and must abort with the remediation hint
    // rather than a bare "could not find a migration".
    spawnMock.mockReturnValue({ status: 0, stdout: '', stderr: '' })

    await expect(
      eqlMigrationCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.info).toHaveBeenCalledWith(
      'If your drizzle.config.ts writes elsewhere, pass --out <dir> so it matches.',
    )
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
