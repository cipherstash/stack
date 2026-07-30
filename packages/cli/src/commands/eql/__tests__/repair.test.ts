import {
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
import { describeSkipReason } from '../../db/rewrite-migrations.js'
import { eqlRepairCommand } from '../repair.js'

// clack is chrome — silence it and spy on the channels the command reports
// through. `step` is on the real clack `log`; omitting it makes the
// per-statement sweep report throw.
const clack = vi.hoisted(() => ({
  spinnerInstance: { start: vi.fn(), stop: vi.fn() },
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

// The applied-state probe is the one part of the command that talks to a
// database. Fake the driver rather than the module that uses it, so the real
// query text and the real timestamp comparison stay under test.
const pgMock = vi.hoisted(() => ({
  connect: vi.fn(),
  query: vi.fn(),
  end: vi.fn(),
  connectionStrings: [] as (string | undefined)[],
}))
vi.mock('pg', () => ({
  default: {
    Client: vi.fn((config: { connectionString?: string }) => {
      pgMock.connectionStrings.push(config?.connectionString)
      return {
        connect: pgMock.connect,
        query: pgMock.query,
        end: pgMock.end,
      }
    }),
  },
}))

// The sweep stays REAL by default — every other test drives it through actual
// SQL on disk. The spy exists only to reach the "sweep threw" branch, with a
// failure the sweep cannot be made to produce from a fixture (EACCES).
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

/** Stand in for `select max(created_at) from drizzle.__drizzle_migrations`. */
function mockLatestAppliedMillis(millis: number | null): void {
  // node-postgres returns bigint columns as strings; the command must cope.
  pgMock.query.mockResolvedValue({
    rows: [{ max_created_at: millis === null ? null : String(millis) }],
  })
}

beforeEach(() => {
  // A stray DATABASE_URL in the developer's shell would silently turn the
  // offline tests into online ones.
  vi.stubEnv('DATABASE_URL', '')
  pgMock.connectionStrings.length = 0
  rewriteMock.spy.mockImplementation(rewriteMock.real)
  // `pg`'s Client.connect/end both return promises, and the probe chains off
  // end() to swallow a teardown failure. A bare vi.fn() returns undefined, so
  // the double has to resolve or that chain throws on a shape the real driver
  // never produces.
  pgMock.connect.mockResolvedValue(undefined)
  pgMock.end.mockResolvedValue(undefined)
})
afterEach(() => {
  vi.unstubAllEnvs()
  vi.clearAllMocks()
})

/** drizzle-kit's journal, with one entry per tag at the given `when`. */
function writeJournal(
  outDir: string,
  entries: { tag: string; when: number }[],
): void {
  mkdirSync(join(outDir, 'meta'), { recursive: true })
  writeFileSync(
    join(outDir, 'meta', '_journal.json'),
    JSON.stringify({
      version: '7',
      dialect: 'postgresql',
      entries: entries.map(({ tag, when }, idx) => ({
        idx,
        version: '7',
        when,
        tag,
        breakpoints: true,
      })),
    }),
  )
}

const BROKEN_ALTER =
  'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE "undefined"."eql_v3_text_search";\n'

/**
 * The corpus a real project has when drizzle-kit emits the broken ALTER: an
 * earlier migration declaring the plaintext column (the sweep is fail-closed
 * and rewrites nothing it cannot see declared), then the ALTER itself.
 */
function writeBrokenCorpus(
  outDir: string,
  opts: { declaredWhen?: number; brokenWhen?: number } = {},
): string {
  mkdirSync(outDir, { recursive: true })
  writeFileSync(
    join(outDir, '0000_declare.sql'),
    'CREATE TABLE "users" ("email" text);\n',
  )
  const broken = join(outDir, '0001_encrypt-email.sql')
  writeFileSync(broken, BROKEN_ALTER)
  writeJournal(outDir, [
    { tag: '0000_declare', when: opts.declaredWhen ?? 1_000 },
    { tag: '0001_encrypt-email', when: opts.brokenWhen ?? 2_000 },
  ])
  return broken
}

describe('eqlRepairCommand — target selection', () => {
  it('exits 1 with an actionable message when no target is given', async () => {
    await expect(eqlRepairCommand({})).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(messages.eql.repairNeedsTarget)
  })
})

describe('eqlRepairCommand — Drizzle', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'stash-eql-repair-'))
  })
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  // Fail closed rather than treat "nothing there" as "nothing to repair": a
  // mistyped --out (or a drizzle.config.ts writing elsewhere) would otherwise
  // report a clean sweep over a directory the command never looked at.
  it('exits 1 naming --out when the output directory does not exist', async () => {
    const out = join(tmp, 'nope')
    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(expect.stringContaining(out))
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('--out'),
    )
  })

  // The journal is the only offline record of which migrations exist and when
  // they were generated — without it the applied-state check has no input at
  // all, so repairing would be guessing. Refuse rather than sweep blind.
  it('exits 1 when meta/_journal.json is missing', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    writeFileSync(join(out, '0000_x.sql'), 'SELECT 1;\n')

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('meta/_journal.json'),
    )
  })

  // Same refusal for a journal that is present but unusable — truncated by a
  // botched merge, or carrying no `entries` array. Both leave the applied-state
  // check with no input, and neither should surface as a raw SyntaxError.
  it.each([
    ['unparseable JSON', '{ "entries": ['],
    ['no entries array', '{ "version": "7" }'],
  ])('exits 1 when the journal is malformed (%s)', async (_label, body) => {
    const out = join(tmp, 'drizzle')
    mkdirSync(join(out, 'meta'), { recursive: true })
    writeFileSync(join(out, 'meta', '_journal.json'), body)

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('meta/_journal.json'),
    )
  })

  // The reason the command exists: repair a broken migration without having to
  // generate a redundant EQL install migration to trigger the sweep.
  it('rewrites an unapplied broken ALTER COLUMN and reports the file', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out)

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).resolves.toBeUndefined()

    const rewritten = readFileSync(broken, 'utf-8')
    expect(rewritten).toContain(
      'ALTER TABLE "users" ADD COLUMN "email_encrypted" "public"."eql_v3_text_search";',
    )
    expect(rewritten).not.toContain('SET DATA TYPE')
    // Add-only: the source column survives for the staged backfill.
    expect(rewritten).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)

    const info = clack.log.info.mock.calls.map((c) => String(c[0]))
    expect(info.some((msg) => msg.includes('Rewrote 1 migration file'))).toBe(
      true,
    )
    expect(clack.log.error).not.toHaveBeenCalled()
  })

  // A clean directory must say so out loud. Silence reads as "the command did
  // not run", and sends the user back to `eql migration --drizzle` — the
  // redundant-install-migration workaround this command exists to remove.
  it('reports success and changes nothing when there is nothing to repair', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    const clean = join(out, '0000_clean.sql')
    const contents = 'CREATE TABLE "users" ("email" text);\n'
    writeFileSync(clean, contents)
    writeJournal(out, [{ tag: '0000_clean', when: 1_000 }])

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).resolves.toBeUndefined()

    expect(readFileSync(clean, 'utf-8')).toBe(contents)
    expect(clack.log.success).toHaveBeenCalledWith(
      messages.eql.repairNothingToDo,
    )
    expect(clack.log.error).not.toHaveBeenCalled()
  })

  // Same fail-closed posture as `eql migration --drizzle`: a statement the
  // sweep could not rewrite still fails at migrate time, so exiting 0 would
  // tell CI the repair had succeeded.
  it('exits 1 and reports the guidance when the sweep leaves a statement behind', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    // Hand-authored `SET DATA TYPE ... USING`: outside the strict matcher, but
    // the broad scan flags it as a near-miss.
    const nearMiss = join(out, '0000_nearmiss.sql')
    writeFileSync(
      nearMiss,
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;\n',
    )
    writeJournal(out, [{ tag: '0000_nearmiss', when: 1_000 }])

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)

    expect(readFileSync(nearMiss, 'utf-8')).toContain('SET DATA TYPE')
    const stepped = clack.log.step.mock.calls.map((c) => String(c[0]))
    expect(
      stepped.some((msg) => msg.includes('falls outside the strict matcher')),
    ).toBe(true)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('unsafe or unverified SQL'),
    )
  })

  // --dry-run must be a true preview: the whole point is inspecting the repair
  // before letting it touch migrations that are about to be applied.
  it('writes nothing under --dry-run but names the file it would rewrite', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out)

    await expect(
      eqlRepairCommand({ drizzle: true, out, dryRun: true }),
    ).resolves.toBeUndefined()

    expect(readFileSync(broken, 'utf-8')).toBe(BROKEN_ALTER)
    const info = clack.log.info.mock.calls.map((c) => String(c[0]))
    expect(info.some((msg) => msg.includes('Would rewrite 1 migration'))).toBe(
      true,
    )
    const stepped = clack.log.step.mock.calls.map((c) => String(c[0]))
    expect(stepped.some((msg) => msg.includes(broken))).toBe(true)
  })

  /**
   * A sweep that throws part way through has already written some rewrites, so
   * the user needs the same partial-work report `eql migration --drizzle` gives
   * (#786) — not an unhandled rejection. Both commands render it through the
   * same helper.
   */
  it('reports a sweep that threw, including the work it had already done', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    writeJournal(out, [{ tag: '0000_x', when: 1_000 }])
    rewriteMock.spy.mockRejectedValueOnce(
      Object.assign(new Error('EACCES: permission denied'), {
        rewritten: [join(out, '0000_x.sql')],
        skipped: [],
        staged: [],
      }),
    )

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)

    const info = clack.log.info.mock.calls.map((c) => String(c[0])).join('\n')
    expect(info).toContain('before the sweep stopped')
    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not sweep'),
    )
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('unsafe or unverified SQL'),
    )
  })

  // `describeStagedReconciliation` is written in the past tense — "the database
  // now has" — because a real sweep has already written the twin. Under
  // --dry-run nothing was written, so printing it verbatim would send the user
  // reconciling a schema against a column that does not exist.
  it('does not claim a twin exists under --dry-run', async () => {
    const out = join(tmp, 'drizzle')
    writeBrokenCorpus(out)

    await eqlRepairCommand({ drizzle: true, out, dryRun: true })

    const warnings = clack.log.warn.mock.calls
      .map((c) => String(c[0]))
      .join('\n')
    expect(warnings).not.toContain('the database now has')
    const info = clack.log.info.mock.calls.map((c) => String(c[0])).join('\n')
    expect(info).toContain(messages.eql.repairDryRunStaged(1))
  })
})

/**
 * The capability `eql migration --drizzle` cannot offer, and the reason this
 * command exists as its own entry point.
 *
 * A matching statement is un-runnable by construction, so the migration almost
 * always failed on apply and is safe to rewrite. The exception is a `jsonb`
 * column changed to a v3 domain on an EMPTY table: the base types are
 * compatible and the envelope CHECK has nothing to reject, so it applies. Once
 * it has, rewriting the .sql leaves it describing a shape the original database
 * never got from it — a fresh CI or staging database replaying the rewritten
 * file diverges from dev, silently.
 */
describe('eqlRepairCommand — applied migrations', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'stash-eql-repair-'))
  })
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true })
  })

  it('refuses to rewrite a migration the database has already applied', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out, { brokenWhen: 2_000 })
    // Drizzle's applied-check is `folderMillis <= max(created_at)`, so a
    // watermark at the broken migration's own `when` means it ran.
    mockLatestAppliedMillis(2_000)

    await expect(
      eqlRepairCommand({
        drizzle: true,
        out,
        databaseUrl: 'postgres://user:pw@localhost:5432/app',
      }),
    ).rejects.toBeInstanceOf(CliExit)

    // Untouched on disk — the whole point.
    expect(readFileSync(broken, 'utf-8')).toBe(BROKEN_ALTER)

    const reported = [
      ...clack.log.warn.mock.calls,
      ...clack.log.error.mock.calls,
      ...clack.log.step.mock.calls,
    ]
      .map((c) => String(c[0]))
      .join('\n')
    // A distinct outcome, not a silent skip: names the file, says it is
    // applied, names the hazard, and points at the staged lifecycle.
    expect(reported).toContain(broken)
    expect(reported.toLowerCase()).toContain('already applied')
    expect(reported).toContain('stash encrypt')
    expect(reported).toContain(messages.eql.repairAppliedHazard)
  })

  // The discriminating half. Without this, an implementation that refused every
  // migration whenever a database was reachable would pass the test above — and
  // would be useless in the flow the command exists for.
  it('still repairs a migration generated after the applied watermark', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out, {
      declaredWhen: 1_000,
      brokenWhen: 2_000,
    })
    // Only the declaring migration ran.
    mockLatestAppliedMillis(1_000)

    await expect(
      eqlRepairCommand({
        drizzle: true,
        out,
        databaseUrl: 'postgres://user:pw@localhost:5432/app',
      }),
    ).resolves.toBeUndefined()

    expect(readFileSync(broken, 'utf-8')).toContain(
      'ADD COLUMN "email_encrypted"',
    )
  })

  /**
   * The offline default, stated as a test so it cannot drift: proceed, but say
   * plainly that applied state was NOT verified.
   *
   * Refusing without a URL would be the fail-closed reading, and it is wrong
   * here — the overwhelmingly common case is a broken migration that could not
   * have applied, in a project whose database may not be reachable from where
   * the repair runs, so a refusal would make the command useless in its own
   * intended flow. The warning names the one genuinely unsafe case and how to
   * get the check.
   */
  it('warns that applied state is unverified without a database URL, and repairs anyway', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out)

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).resolves.toBeUndefined()

    expect(readFileSync(broken, 'utf-8')).toContain(
      'ADD COLUMN "email_encrypted"',
    )
    expect(clack.log.warn).toHaveBeenCalledWith(
      messages.eql.repairAppliedUnverified,
    )
    // No connection attempt at all — the command stays offline.
    expect(pgMock.connect).not.toHaveBeenCalled()
  })

  // DATABASE_URL is the documented second tier of the URL resolver, so the
  // check must run off it too — a user with it exported gets the safety without
  // repeating it on the command line.
  it('runs the applied check from DATABASE_URL when no flag is passed', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out, { brokenWhen: 2_000 })
    mockLatestAppliedMillis(2_000)
    vi.stubEnv('DATABASE_URL', 'postgres://user:pw@localhost:5432/from-env')

    await expect(
      eqlRepairCommand({ drizzle: true, out }),
    ).rejects.toBeInstanceOf(CliExit)

    expect(readFileSync(broken, 'utf-8')).toBe(BROKEN_ALTER)
    expect(pgMock.connectionStrings).toEqual([
      'postgres://user:pw@localhost:5432/from-env',
    ])
  })

  // Pins the mechanism, not just the outcome: drizzle decides on the timestamp
  // watermark in its own ledger. A hash comparison would be modelling something
  // drizzle does not do (`pg-core/dialect.js:62` writes the hash and never
  // reads it), and would re-run migrations drizzle considers done.
  it('reads the watermark from drizzle.__drizzle_migrations', async () => {
    const out = join(tmp, 'drizzle')
    writeBrokenCorpus(out)
    mockLatestAppliedMillis(1_000)

    await eqlRepairCommand({
      drizzle: true,
      out,
      databaseUrl: 'postgres://user:pw@localhost:5432/app',
    })

    const sql = String(pgMock.query.mock.calls[0]?.[0])
    // Quoted, because the relation is now parameterised by --migrations-table
    // and reaches the query as text.
    expect(sql).toContain('"drizzle"."__drizzle_migrations"')
    expect(sql).toContain('created_at')
    expect(sql).not.toContain('hash')
  })

  // An empty (or absent-but-readable) ledger means nothing has run yet, so
  // everything is repairable. Reported rather than silent, because "no rows"
  // and "check did not run" must not look the same to the user.
  it('treats an empty ledger as nothing applied', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out)
    mockLatestAppliedMillis(null)

    await expect(
      eqlRepairCommand({
        drizzle: true,
        out,
        databaseUrl: 'postgres://user:pw@localhost:5432/app',
      }),
    ).resolves.toBeUndefined()

    expect(readFileSync(broken, 'utf-8')).toContain(
      'ADD COLUMN "email_encrypted"',
    )
    expect(clack.log.info).toHaveBeenCalledWith(
      messages.eql.repairNothingApplied,
    )
  })

  /**
   * An ABSENT ledger is ambiguous in a way an empty one is not. It means either
   * `drizzle-kit migrate` never ran here, or the project set `migrations.table`
   * / `migrations.schema` in drizzle.config.ts and the probe looked in the
   * wrong place. The command cannot tell those apart, so it must not report the
   * confident "nothing applied" — that is the fail-open case: a project with a
   * custom ledger gets told every migration is repairable while its database
   * has applied plenty.
   */
  it.each([
    ['undefined_table', '42P01'],
    ['invalid_schema_name', '3F000'],
  ])('does not claim nothing is applied when the ledger (%s) is absent', async (_l, code) => {
    const out = join(tmp, 'drizzle')
    writeBrokenCorpus(out)
    pgMock.query.mockRejectedValue(
      Object.assign(new Error('relation does not exist'), { code }),
    )

    await eqlRepairCommand({
      drizzle: true,
      out,
      databaseUrl: 'postgres://user:pw@localhost:5432/app',
    })

    expect(clack.log.info).not.toHaveBeenCalledWith(
      messages.eql.repairNothingApplied,
    )
    const warned = clack.log.warn.mock.calls.map((c) => String(c[0])).join('\n')
    // Names where it looked, and the config key that would move it — a
    // warning the user cannot act on is not much better than silence.
    expect(warned).toContain('drizzle.__drizzle_migrations')
    expect(warned).toContain('--migrations-table')
  })

  /**
   * Applied files carry TWO kinds of statement, and they need different words.
   *
   * One the rewriter would have repaired — refusing it is about the applied
   * hazard, and `repairAppliedHazard` is the right explanation. One it would
   * have left alone regardless (here `source-unknown`: nothing in the corpus
   * declares the column) — its applied-ness is irrelevant, and the actionable
   * thing is the skip reason. Reporting the second under the hazard banner
   * swaps guidance the user can act on for an explanation that does not apply.
   */
  it('gives an applied near-miss its skip guidance, not the rewrite hazard', async () => {
    const out = join(tmp, 'drizzle')
    mkdirSync(out, { recursive: true })
    // No CREATE TABLE anywhere, so the sweep cannot prove the source type.
    const undeclared = join(out, '0000_encrypt-orphan.sql')
    writeFileSync(
      undeclared,
      'ALTER TABLE "ghosts" ALTER COLUMN "note" SET DATA TYPE "undefined"."eql_v3_text_search";\n',
    )
    writeJournal(out, [{ tag: '0000_encrypt-orphan', when: 1_000 }])
    mockLatestAppliedMillis(1_000)

    await expect(
      eqlRepairCommand({
        drizzle: true,
        out,
        databaseUrl: 'postgres://user:pw@localhost:5432/app',
      }),
    ).rejects.toBeInstanceOf(CliExit)

    const reported = [
      ...clack.log.warn.mock.calls,
      ...clack.log.error.mock.calls,
      ...clack.log.step.mock.calls,
    ]
      .map((c) => String(c[0]))
      .join('\n')
    expect(reported).toContain(describeSkipReason('source-unknown'))
    expect(reported).not.toContain(messages.eql.repairAppliedHazard)
  })

  /**
   * The actionable half of the absent-ledger warning. Without this the warning
   * names a flag that does nothing, and a project with a custom ledger has no
   * way to get the check at all.
   */
  it('queries the ledger named by --migrations-table', async () => {
    const out = join(tmp, 'drizzle')
    writeBrokenCorpus(out)
    mockLatestAppliedMillis(1_000)

    await eqlRepairCommand({
      drizzle: true,
      out,
      databaseUrl: 'postgres://user:pw@localhost:5432/app',
      migrationsTable: 'audit.applied_migrations',
    })

    const sql = String(pgMock.query.mock.calls[0]?.[0])
    expect(sql).toContain('"audit"."applied_migrations"')
    expect(sql).not.toContain('__drizzle_migrations')
  })

  /**
   * The relation is the one part of the query built from user text. It is
   * quoted, so it cannot break out — but a value that is not a plain
   * `[schema.]table` becomes a quoted identifier no database has, and the
   * resulting "relation does not exist" would be reported as an ABSENT ledger:
   * a typo would silently downgrade the check the flag was passed to get.
   * Reject it before connecting instead.
   */
  it.each([
    ['a statement terminator', '__drizzle_migrations; drop table users --'],
    ['too many parts', 'db.drizzle.__drizzle_migrations'],
    ['an empty part', 'drizzle.'],
    ['a quoted identifier', '"drizzle"."__drizzle_migrations"'],
  ])('rejects a --migrations-table containing %s', async (_label, migrationsTable) => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out)

    await expect(
      eqlRepairCommand({
        drizzle: true,
        out,
        databaseUrl: 'postgres://user:pw@localhost:5432/app',
        migrationsTable,
      }),
    ).rejects.toBeInstanceOf(CliExit)

    // Never reached the database, and never touched the migration.
    expect(pgMock.query).not.toHaveBeenCalled()
    expect(readFileSync(broken, 'utf-8')).toBe(BROKEN_ALTER)
  })

  // A bare table name is the common case — drizzle's `migrations.table` without
  // a `migrations.schema`. It must resolve via search_path, not be forced into
  // the `drizzle` schema.
  it('accepts an unqualified --migrations-table', async () => {
    const out = join(tmp, 'drizzle')
    writeBrokenCorpus(out)
    mockLatestAppliedMillis(1_000)

    await eqlRepairCommand({
      drizzle: true,
      out,
      databaseUrl: 'postgres://user:pw@localhost:5432/app',
      migrationsTable: 'my_migrations',
    })

    expect(String(pgMock.query.mock.calls[0]?.[0])).toContain('"my_migrations"')
  })

  // An absent ledger still REPAIRS — the overwhelmingly common cause is that
  // drizzle-kit migrate never ran, and refusing there would make the command
  // useless in the flow it exists for. Only the claim of certainty is dropped.
  it('still repairs when the ledger is absent', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out)
    pgMock.query.mockRejectedValue(
      Object.assign(new Error('relation does not exist'), { code: '42P01' }),
    )

    await expect(
      eqlRepairCommand({
        drizzle: true,
        out,
        databaseUrl: 'postgres://user:pw@localhost:5432/app',
      }),
    ).resolves.toBeUndefined()

    expect(readFileSync(broken, 'utf-8')).toContain(
      'ADD COLUMN "email_encrypted"',
    )
  })

  /**
   * The asymmetry that matters: passing --database-url is a request to be
   * protected from rewriting applied migrations. If the probe cannot answer,
   * carrying on as if nothing were applied would hand the user the exact drift
   * they asked to avoid, having told them the check was on.
   */
  it('exits 1 without rewriting anything when the applied check itself fails', async () => {
    const out = join(tmp, 'drizzle')
    const broken = writeBrokenCorpus(out)
    pgMock.connect.mockRejectedValue(
      Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' }),
    )

    await expect(
      eqlRepairCommand({
        drizzle: true,
        out,
        databaseUrl: 'postgres://user:pw@localhost:5432/app',
      }),
    ).rejects.toBeInstanceOf(CliExit)

    expect(readFileSync(broken, 'utf-8')).toBe(BROKEN_ALTER)
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('connection refused'),
    )
    // Every path out of the command closes the banner it opened.
    expect(clack.outro).toHaveBeenCalledWith('Repair incomplete.')
  })
})
