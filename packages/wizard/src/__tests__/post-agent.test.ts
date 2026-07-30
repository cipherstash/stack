import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runPostAgentSteps } from '../lib/post-agent.js'
import type { DetectedPackageManager } from '../lib/types.js'

// Mock the child_process module
vi.mock('node:child_process')

// Only `confirm` is replaced — the log/spinner calls stay real so the module's
// output paths still execute.
vi.mock('@clack/prompts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@clack/prompts')>()
  return { ...actual, confirm: vi.fn(async () => false) }
})

// Wraps the REAL sweep, so every test below still exercises it for free. Two
// cases override it, both because the state they need is not reachable through
// the real filesystem from here: the empty-error-`message` case, and the
// partial-set case, which needs the sweep to throw mid-rewrite-loop rather than
// during its read pass. Each override says so at the call site; prefer a real
// fixture for anything else.
vi.mock('../lib/rewrite-migrations.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../lib/rewrite-migrations.js')>()
  return { ...actual, sweepMigrationDirs: vi.fn(actual.sweepMigrationDirs) }
})

import * as childProcess from 'node:child_process'
import * as p from '@clack/prompts'
import { sweepMigrationDirs } from '../lib/rewrite-migrations.js'

const bun: DetectedPackageManager = {
  name: 'bun',
  installCommand: 'bun add',
  runCommand: 'bun run',
  execCommand: 'bunx',
}

describe('runPostAgentSteps execution commands', () => {
  beforeEach(() => {
    vi.mocked(childProcess.execSync).mockClear()
    vi.mocked(childProcess.execSync).mockImplementation(() => Buffer.from(''))
  })

  it('reads legacy usesProxy context without running or recommending retired db push', async () => {
    const info = vi.spyOn(p.log, 'info')

    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: bun,
      gathered: {
        installCommand: 'bun add @cipherstash/stack',
        hasStashConfig: true,
        usesProxy: true,
      } as never,
    })

    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).not.toContain('bunx stash db push')
    expect(info).not.toHaveBeenCalledWith(expect.stringMatching(/db push/i))
  })

  it('executes eql install using the detected runner (bun → bunx) and ignores legacy usesProxy=true', async () => {
    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: bun,
      gathered: {
        installCommand: 'bun add @cipherstash/stack',
        hasStashConfig: false,
        usesProxy: true,
        // Other GatheredContext fields aren't read in this code path; cast for the test.
      } as never,
    })

    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).toContain('bunx stash eql install')
    expect(commands).not.toContain('bunx stash db push')
    // Sanity: no leftover npx forms for the cipherstash binaries.
    for (const cmd of commands) {
      expect(cmd).not.toMatch(/^npx @cipherstash/)
    }
  })

  it('skips eql install when hasStashConfig=true and ignores legacy usesProxy=true', async () => {
    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: bun,
      gathered: {
        installCommand: 'bun add @cipherstash/stack',
        hasStashConfig: true,
        usesProxy: true,
      } as never,
    })
    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).not.toContain('bunx stash db push')
    expect(commands).not.toContain('bunx stash eql install')
  })

  it('falls back to npx when packageManager is undefined and ignores legacy usesProxy=true', async () => {
    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: undefined,
      gathered: {
        installCommand: 'npm install @cipherstash/stack',
        hasStashConfig: false,
        usesProxy: true,
      } as never,
    })
    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).toContain('npx stash eql install')
    expect(commands).not.toContain('npx stash db push')
  })

  it('never runs retired db push when legacy usesProxy=false', async () => {
    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: bun,
      gathered: {
        installCommand: 'bun add @cipherstash/stack',
        hasStashConfig: false,
        usesProxy: false,
      } as never,
    })

    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).not.toContain('bunx stash db push')
    expect(commands).toContain('bunx stash eql install')
  })
})

// The sweep's own warning says "do NOT run the migration" on a populated table.
// Defaulting the very next prompt to Yes invites the mistake the warning exists
// to prevent — so a sweep that touched anything flips the default to No.
describe('drizzle migrate prompt after a staged rewrite', () => {
  let cwd: string

  const runDrizzle = () =>
    runPostAgentSteps({
      cwd,
      integration: 'drizzle',
      packageManager: bun,
      gathered: {
        installCommand: 'bun add @cipherstash/stack',
        hasStashConfig: true,
        usesProxy: false,
      } as never,
    })

  /**
   * Make `dir` a drizzle-kit OUTPUT directory. The sweep now requires the
   * `meta/_journal.json` drizzle-kit maintains, because `migrations/` and
   * `src/db/migrations/` are generic names other tools use, so the wizard must
   * not edit them unless drizzle-kit's journal proves ownership.
   */
  const makeDrizzleOut = (dir: string): string => {
    const abs = path.join(cwd, dir)
    fs.mkdirSync(path.join(abs, 'meta'), { recursive: true })
    fs.writeFileSync(
      path.join(abs, 'meta', '_journal.json'),
      JSON.stringify({ version: '7', dialect: 'postgresql', entries: [] }),
    )
    return abs
  }

  beforeEach(() => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'wizard-post-agent-'))
    vi.mocked(p.confirm).mockClear()
  })

  afterEach(() => {
    // Every test here writes a real temp tree; without this they accumulate in
    // os.tmpdir() for the life of the machine.
    fs.rmSync(cwd, { recursive: true, force: true })
  })

  it('defaults to Yes when the sweep changed nothing', async () => {
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_init.sql'),
      'CREATE TABLE "users" ("id" integer PRIMARY KEY);\n',
    )

    await runDrizzle()

    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(true)
    // Pin that the clean message carries none of the stale destructive or
    // fail-closed wording.
    const message = String(options?.message)
    expect(message).not.toContain('DESTROYS data')
    expect(message).not.toContain('flagged for review')
    expect(message).not.toContain('could not check')
  })

  it('defaults to Yes and explains the staged addition when a file was rewritten', async () => {
    const info = vi.spyOn(p.log, 'info').mockImplementation(() => {})
    makeDrizzleOut('drizzle')
    // The sweep is fail-closed: it rewrites a column only when the corpus
    // positively declares it (and it isn't already encrypted). A real drizzle
    // corpus carries this declaration in an earlier migration — supply it so
    // the fixture matches what the sweep actually requires, and the ALTER
    // below is genuinely rewritten rather than skipped as source-unknown.
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await runDrizzle()

    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(true)
    expect(String(options?.message)).toContain('staged encrypted columns')
    expect(String(options?.message)).toContain('preserves the source column')

    // Pin the on-disk effect so a skipped source-unknown statement cannot make
    // this prompt test pass accidentally.
    const swept = fs.readFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'utf-8',
    )
    expect(swept).toContain('ADD COLUMN "email_encrypted"')
    expect(swept).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
    expect(swept).not.toContain('SET DATA TYPE')

    // The per-directory report takes the clean arm of its message: a sweep that
    // finished must not borrow the "before the sweep stopped" wording the
    // partial path uses. Anchored on `in drizzle/` so the cross-directory
    // summary ("in the drizzle output") cannot satisfy it instead.
    expect(info).toHaveBeenCalledWith(
      expect.stringContaining(
        'in drizzle/ to add staged encrypted columns while preserving the source columns',
      ),
    )
    expect(info).not.toHaveBeenCalledWith(
      expect.stringContaining('before the sweep stopped'),
    )
    info.mockRestore()
  })

  it('fails before prompting when a statement was flagged rather than rewritten', async () => {
    const warn = vi.spyOn(p.log, 'warn').mockImplementation(() => {})
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0001_using.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;\n',
    )

    await expect(runDrizzle()).rejects.toThrow('unsafe or unverified SQL')
    expect(p.confirm).not.toHaveBeenCalled()
    expect(
      warn.mock.calls.filter(([message]) =>
        String(message).includes('rewrite left alone'),
      ),
    ).toHaveLength(1)
    warn.mockRestore()
  })

  // A directory whose sweep threw contributes 0 to both totals, so a failed
  // sweep used to be indistinguishable from a clean one: prompt defaulting to
  // Yes over migrations nobody checked. Unknown is not the same as safe.
  it('fails before prompting when a directory could not be swept at all', async () => {
    const warn = vi.spyOn(p.log, 'warn').mockImplementation(() => {})
    // A directory named `*.sql` makes readFile throw EISDIR mid-sweep.
    makeDrizzleOut('drizzle')
    fs.mkdirSync(path.join(cwd, 'drizzle', '0001_alter.sql'))

    await expect(runDrizzle()).rejects.toThrow('unsafe or unverified SQL')
    expect(p.confirm).not.toHaveBeenCalled()
    expect(
      warn.mock.calls.filter(([message]) =>
        String(message).includes('Could not rewrite migrations'),
      ),
    ).toHaveLength(1)
    expect(warn).not.toHaveBeenCalledWith(
      expect.stringContaining('Could not fully rewrite migrations'),
    )
    warn.mockRestore()
  })

  // The cross-directory summary is printed off `totals.rewritten`, which counts
  // a clean directory and a failed one alike. Printing "…while preserving the
  // source columns" after a directory failed re-asserts the reassuring framing
  // the per-directory report deliberately drops, for a sweep that did not
  // finish. The per-directory lines already name every file, so the summary has
  // nothing to add on that path.
  it('does not summarise the sweep as clean when another directory failed', async () => {
    const warn = vi.spyOn(p.log, 'warn').mockImplementation(() => {})
    const info = vi.spyOn(p.log, 'info').mockImplementation(() => {})
    // drizzle/ declares its column, so its ALTER is rewritten cleanly...
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )
    // ...while migrations/ cannot be swept at all: a directory named `*.sql`
    // makes readFile throw EISDIR mid-sweep.
    makeDrizzleOut('migrations')
    fs.mkdirSync(path.join(cwd, 'migrations', '0001_alter.sql'))

    await expect(runDrizzle()).rejects.toThrow('unsafe or unverified SQL')

    expect(info).not.toHaveBeenCalledWith(
      expect.stringContaining('in the drizzle output'),
    )
    // The per-directory report still stands on its own for the clean directory.
    expect(info).toHaveBeenCalledWith(
      expect.stringContaining(
        'in drizzle/ to add staged encrypted columns while preserving the source columns',
      ),
    )
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not rewrite migrations in migrations'),
    )
    info.mockRestore()
    warn.mockRestore()
  })

  // A sweep that throws part-way through has already written the files it got
  // to, and may have flagged statements before it stopped —
  // `sweepMigrationDirs` propagates both on the failure path. The reporting used
  // to sit after a `continue`, so the wizard surfaced neither: the user was told
  // a directory failed without being told which of its files had changed or
  // what it had flagged. The CLI twin has always reported the partial set
  // (`packages/cli/src/commands/eql/migration.ts`). #837.
  //
  // Mocked, unlike the tests above: the throw has to land *inside* the rewrite
  // loop to leave a partial set behind, which needs a mid-loop `writeFile`
  // failure (see `rewrite-migrations.test.ts`, "reports files rewritten before a
  // later write failure"). The real filesystem errors reachable from here throw
  // during the read pass, before anything is rewritten or flagged.
  it('names the files rewritten and statements flagged before a failed sweep stopped', async () => {
    const warn = vi.spyOn(p.log, 'warn').mockImplementation(() => {})
    const info = vi.spyOn(p.log, 'info').mockImplementation(() => {})
    const step = vi.spyOn(p.log, 'step').mockImplementation(() => {})
    vi.mocked(sweepMigrationDirs).mockResolvedValueOnce([
      {
        dir: 'drizzle',
        rewritten: ['drizzle/0001_email.sql'],
        skipped: [
          {
            file: 'drizzle/0002_total.sql',
            statement:
              'ALTER TABLE "orders" ALTER COLUMN "total" SET DATA TYPE eql_v3_text_search;',
            reason: 'source-unknown',
          },
        ],
        error: 'EACCES: permission denied, open drizzle/0003_name.sql',
      },
    ])

    await expect(runDrizzle()).rejects.toThrow('unsafe or unverified SQL')

    expect(p.confirm).not.toHaveBeenCalled()
    // The failure itself is still reported...
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not rewrite migrations in drizzle'),
    )
    // ...and so is what it changed on the way there, named file by file.
    expect(info).toHaveBeenCalledWith(
      expect.stringContaining('before the sweep stopped'),
    )
    expect(step).toHaveBeenCalledWith(
      expect.stringContaining('drizzle/0001_email.sql'),
    )
    // ...as is what it flagged, with the reason the user has to act on.
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('rewrite left alone'),
    )
    expect(step).toHaveBeenCalledWith(
      expect.stringContaining('drizzle/0002_total.sql'),
    )
    expect(step).toHaveBeenCalledWith(
      expect.stringContaining('could not find where this column was declared'),
    )
    step.mockRestore()
    info.mockRestore()
    warn.mockRestore()
  })

  // `error` is built as `err instanceof Error ? err.message : String(err)`, and
  // `new Error()` has an empty message — so a thrown error can arrive as `''`.
  // Testing it for truthiness rather than presence would drop that directory
  // back into the fail-open default, which is the exact bug above wearing a
  // different hat.
  it('treats an empty error message as a failed sweep, not a clean one', async () => {
    vi.mocked(sweepMigrationDirs).mockResolvedValueOnce([
      { dir: 'drizzle', rewritten: [], skipped: [], staged: [], error: '' },
    ])

    await expect(runDrizzle()).rejects.toThrow('unsafe or unverified SQL')
    expect(p.confirm).not.toHaveBeenCalled()
  })

  /**
   * #836, item 2. The wizard's agent edited schema.ts to declare the column as
   * the encrypted domain — that edit is what made drizzle-kit emit the
   * impossible `SET DATA TYPE`. After the add-only sweep the database has both
   * columns, while schema.ts and the snapshot still describe only the old one,
   * and `drizzle-kit generate` shows nothing because those two agree with each
   * other. The wizard must say so before it offers to run the migration.
   */
  it('warns that schema.ts and the snapshot diverged after staging a twin', async () => {
    const warn = vi.spyOn(p.log, 'warn').mockImplementation(() => {})
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await runDrizzle()

    const warnings = warn.mock.calls.map(([m]) => String(m)).join('\n')
    expect(warnings).toContain('users:')
    expect(warnings).toContain('"email_encrypted" eql_v3_text_search')
    expect(warnings).toContain('drizzle-kit generate` will NOT warn you')
    expect(warnings).toContain('column already exists')
    // Said BEFORE the migrate prompt, so the user decides with it in hand.
    expect(p.confirm).toHaveBeenCalled()
    warn.mockRestore()
  })

  // Nothing staged means nothing diverged: the notice must not fire, or it sends
  // the user editing a schema that is already consistent.
  it('does not warn about reconciliation when nothing was staged', async () => {
    const warn = vi.spyOn(p.log, 'warn').mockImplementation(() => {})
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_init.sql'),
      'CREATE TABLE "widgets" ("id" integer PRIMARY KEY);\n',
    )

    await runDrizzle()

    const warnings = warn.mock.calls.map(([m]) => String(m)).join('\n')
    expect(warnings).not.toContain('drizzle-kit generate` will NOT warn you')
    warn.mockRestore()
  })

  // The wizard ships scanning drizzle/, migrations/ and src/db/migrations/ and
  // indexes each SEPARATELY — the per-directory index is the mechanism the
  // fail-closed rule exists to make safe. Every test above uses only drizzle/,
  // so shrinking the shipped constant to ['drizzle'], or short-circuiting the
  // aggregation loop after the first directory, leaves them all green. These two
  // put the actionable content in a NON-first directory so those regressions
  // fail.
  it('sweeps a candidate directory other than the first', async () => {
    // drizzle/ exists but has nothing to do; the rewrite lives in migrations/.
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_init.sql'),
      'CREATE TABLE "widgets" ("id" integer PRIMARY KEY);\n',
    )
    makeDrizzleOut('migrations')
    fs.writeFileSync(
      path.join(cwd, 'migrations', '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    fs.writeFileSync(
      path.join(cwd, 'migrations', '0001_encrypt.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await runDrizzle()

    // The migrations/ ALTER was rewritten — proof the second directory was
    // swept, not just drizzle/.
    const swept = fs.readFileSync(
      path.join(cwd, 'migrations', '0001_encrypt.sql'),
      'utf-8',
    )
    expect(swept).toContain('ADD COLUMN "email_encrypted"')
    expect(swept).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
    expect(swept).not.toContain('SET DATA TYPE')
    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(true)
    expect(String(options?.message)).toContain('staged encrypted columns')
  })

  // The other half of the test above. `migrations/` is swept when it is a
  // drizzle output directory — and must NOT be when it belongs to Knex,
  // node-pg-migrate, Flyway or hand-rolled psql, all of which use that name.
  // The wizard was never pointed at such a directory (#772 review, finding 5).
  it('leaves a migrations/ directory that is not a drizzle output untouched', async () => {
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_init.sql'),
      'CREATE TABLE "widgets" ("id" integer PRIMARY KEY);\n',
    )
    // A foreign migration history: self-contained, so the fail-closed
    // `declared` rule would happily pass it.
    fs.mkdirSync(path.join(cwd, 'migrations'), { recursive: true })
    const foreign = path.join(cwd, 'migrations', '002_encrypt.sql')
    const foreignSql = [
      'CREATE TABLE "patients" ("ssn" text);',
      'ALTER TABLE "patients" ALTER COLUMN "ssn" SET DATA TYPE eql_v3_text_search;',
      '',
    ].join('\n')
    fs.writeFileSync(foreign, foreignSql)

    // Only `confirm` is mocked at module level; spy on the log so the
    // "passed over" notice can be asserted.
    const info = vi.spyOn(p.log, 'info').mockImplementation(() => {})

    await runDrizzle()

    expect(fs.readFileSync(foreign, 'utf-8')).toBe(foreignSql)
    expect(fs.readFileSync(foreign, 'utf-8')).not.toContain('DROP COLUMN')
    // Nothing was rewritten or flagged, so the prompt stays on its clean arm.
    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(true)
    // But the user is told the directory was passed over, so a genuine drizzle
    // output whose meta/ went missing does not just look clean.
    const logged = info.mock.calls.flat().join('\n')
    expect(logged).toContain('migrations/')
    expect(logged).toContain('meta/_journal.json')
    info.mockRestore()
  })

  it('aggregates a rewrite in one directory with a flag in another', async () => {
    // drizzle/ declares email, so its ALTER is rewritten.
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_declare.sql'),
      'CREATE TABLE "users" ("email" text);\n',
    )
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )
    // migrations/ never declares its column, so its ALTER is source-unknown.
    makeDrizzleOut('migrations')
    const flagged = path.join(cwd, 'migrations', '0001_encrypt.sql')
    const flaggedSql =
      'ALTER TABLE "orders" ALTER COLUMN "total" SET DATA TYPE eql_v3_text_search;\n'
    fs.writeFileSync(flagged, flaggedSql)

    await expect(runDrizzle()).rejects.toThrow('unsafe or unverified SQL')

    // drizzle/ was rewritten...
    const rewritten = fs.readFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'utf-8',
    )
    expect(rewritten).toContain('ADD COLUMN "email_encrypted"')
    expect(rewritten).not.toMatch(/\b(?:DROP|RENAME)\s+COLUMN\b/i)
    // ...and migrations/ was left untouched, flagged rather than rewritten.
    expect(fs.readFileSync(flagged, 'utf-8')).toBe(flaggedSql)
    expect(p.confirm).not.toHaveBeenCalled()
  })
})
