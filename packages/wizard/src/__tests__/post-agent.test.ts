import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
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

  it('executes eql install using the detected runner (bun → bunx)', async () => {
    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: bun,
      gathered: {
        installCommand: 'bun add @cipherstash/stack',
        hasStashConfig: false,
        // Other GatheredContext fields aren't read in this code path; cast for the test.
      } as never,
    })

    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).toContain('bunx stash eql install')
    // Sanity: no leftover npx forms for the cipherstash binaries.
    for (const cmd of commands) {
      expect(cmd).not.toMatch(/^npx @cipherstash/)
    }
  })

  it('skips eql install when hasStashConfig=true', async () => {
    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: bun,
      gathered: {
        installCommand: 'bun add @cipherstash/stack',
        hasStashConfig: true,
      } as never,
    })
    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).not.toContain('bunx stash eql install')
  })

  it('falls back to npx when packageManager is undefined', async () => {
    await runPostAgentSteps({
      cwd: '/tmp/fake',
      integration: 'supabase',
      packageManager: undefined,
      gathered: {
        installCommand: 'npm install @cipherstash/stack',
        hasStashConfig: false,
      } as never,
    })
    const commands = vi
      .mocked(childProcess.execSync)
      .mock.calls.map((c) => c[0] as string)
    expect(commands).toContain('npx stash eql install')
  })

  // `stash db push` writes `eql_v2_configuration`, which only ever applied to
  // EQL v2 with CipherStash Proxy. The wizard used to run it whenever the
  // removed `usesProxy` flag was set; with no v2 surface left there is no
  // condition under which post-agent should shell out to it.
  it('never runs `stash db push`', async () => {
    for (const hasStashConfig of [false, true]) {
      vi.mocked(childProcess.execSync).mockClear()
      await runPostAgentSteps({
        cwd: '/tmp/fake',
        integration: 'supabase',
        packageManager: bun,
        gathered: {
          installCommand: 'bun add @cipherstash/stack',
          hasStashConfig,
        } as never,
      })
      const commands = vi
        .mocked(childProcess.execSync)
        .mock.calls.map((c) => c[0] as string)
      for (const cmd of commands) {
        expect(cmd).not.toMatch(/stash db push/)
      }
    }
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
      } as never,
    })

  beforeEach(() => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'wizard-post-agent-'))
    vi.mocked(p.confirm).mockClear()
  })

  it('defaults to Yes when the sweep changed nothing', async () => {
    fs.mkdirSync(path.join(cwd, 'drizzle'))
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0000_init.sql'),
      'CREATE TABLE "users" ("id" integer PRIMARY KEY);\n',
    )

    await runDrizzle()

    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(true)
  })

  it('defaults to No, and says why, when a file was rewritten', async () => {
    fs.mkdirSync(path.join(cwd, 'drizzle'))
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
    fs.mkdirSync(path.join(cwd, 'drizzle'))
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
    fs.mkdirSync(path.join(cwd, 'drizzle'))
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
})
