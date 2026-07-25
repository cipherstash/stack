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

// Wraps the REAL sweep, so every test below still exercises it for free. Only
// the empty-message case overrides it, because no real filesystem error is
// reachable with a blank `message`.
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

  it('executes eql install/db push using the detected runner (bun → bunx) when usesProxy=true', async () => {
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
    expect(commands).toContain('bunx stash db push')
    // Sanity: no leftover npx forms for the cipherstash binaries.
    for (const cmd of commands) {
      expect(cmd).not.toMatch(/^npx @cipherstash/)
    }
  })

  it('skips eql install when hasStashConfig=true and still uses bunx for db push when usesProxy=true', async () => {
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
    expect(commands).toContain('bunx stash db push')
    expect(commands).not.toContain('bunx stash eql install')
  })

  it('falls back to npx when packageManager is undefined and usesProxy=true', async () => {
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
    expect(commands).toContain('npx stash db push')
  })

  it('skips db push when usesProxy=false', async () => {
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
describe('drizzle migrate prompt after a destructive rewrite', () => {
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
   * `src/db/migrations/` are generic names other tools use and this sweep
   * emits `DROP COLUMN`.
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
    // The clean arm is the last of a 4-way nested ternary; the negative
    // assertions that guard the other arms' wording never run against this one.
    // A mis-nested arm here would ship a destruction/flag/unchecked warning to a
    // user with nothing to sweep, and asserting only `initialValue` would miss
    // it — so pin that the clean message carries none of those phrases.
    const message = String(options?.message)
    expect(message).not.toContain('DESTROYS data')
    expect(message).not.toContain('flagged for review')
    expect(message).not.toContain('could not check')
  })

  it('defaults to No, and says why, when a file was rewritten', async () => {
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
    expect(options?.initialValue).toBe(false)
    expect(String(options?.message)).toContain('DESTROYS data')

    // Assert the REWRITE actually happened, not just that the prompt defaulted
    // to No — both this test and its `source-unknown` sibling below produce
    // `initialValue: false` and a message containing "DESTROYS data" is the
    // only thing that used to distinguish them, and that came from the same
    // skipped-statement branch too. Without the 0000_declare.sql fixture the
    // ALTER is skipped as source-unknown rather than rewritten, so pin the
    // on-disk effect a genuine rewrite leaves behind.
    const swept = fs.readFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'utf-8',
    )
    expect(swept).toContain('DROP COLUMN')
    expect(swept).not.toContain('SET DATA TYPE')
  })

  it('defaults to No when a statement was flagged rather than rewritten', async () => {
    makeDrizzleOut('drizzle')
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0001_using.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search USING (email)::eql_v3_text_search;\n',
    )

    await runDrizzle()

    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(false)
    // Nothing was rewritten here — the statement was left on disk and merely
    // flagged — so the prompt must not claim data destruction the way the
    // genuinely-rewritten case above does.
    expect(String(options?.message)).not.toContain('DESTROYS data')
    expect(String(options?.message)).toContain('flagged for review')
  })

  // A directory whose sweep threw contributes 0 to both totals, so a failed
  // sweep used to be indistinguishable from a clean one: prompt defaulting to
  // Yes over migrations nobody checked. Unknown is not the same as safe.
  it('defaults to No when a directory could not be swept at all', async () => {
    // A directory named `*.sql` makes readFile throw EISDIR mid-sweep.
    makeDrizzleOut('drizzle')
    fs.mkdirSync(path.join(cwd, 'drizzle', '0001_alter.sql'))

    await runDrizzle()

    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(false)
    // Nothing is known about that directory, so the prompt must not claim the
    // migration destroys data — only that it went unchecked.
    expect(String(options?.message)).not.toContain('DESTROYS data')
    expect(String(options?.message)).toContain('drizzle/')
    expect(String(options?.message)).toContain('could not check 1 directory')
  })

  // `error` is built as `err instanceof Error ? err.message : String(err)`, and
  // `new Error()` has an empty message — so a thrown error can arrive as `''`.
  // Testing it for truthiness rather than presence would drop that directory
  // back into the fail-open default, which is the exact bug above wearing a
  // different hat.
  it('treats an empty error message as a failed sweep, not a clean one', async () => {
    vi.mocked(sweepMigrationDirs).mockResolvedValueOnce([
      { dir: 'drizzle', rewritten: [], skipped: [], error: '' },
    ])

    await runDrizzle()

    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(false)
    expect(String(options?.message)).toContain('could not check 1 directory')
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
    expect(swept).toContain('DROP COLUMN')
    expect(swept).not.toContain('SET DATA TYPE')
    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(false)
    expect(String(options?.message)).toContain('DESTROYS data')
  })

  // The other half of the test above. `migrations/` is swept when it is a
  // drizzle output directory — and must NOT be when it belongs to Knex,
  // node-pg-migrate, Flyway or hand-rolled psql, all of which use that name.
  // The wizard was never pointed at such a directory, and this sweep emits
  // DROP COLUMN (#772 review, finding 5).
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

    await runDrizzle()

    // drizzle/ was rewritten...
    const rewritten = fs.readFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'utf-8',
    )
    expect(rewritten).toContain('DROP COLUMN')
    // ...and migrations/ was left untouched, flagged rather than rewritten.
    expect(fs.readFileSync(flagged, 'utf-8')).toBe(flaggedSql)
    // A rewrite anywhere makes the prompt destructive and defaults it to No.
    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(false)
    expect(String(options?.message)).toContain('DESTROYS data')
  })
})
