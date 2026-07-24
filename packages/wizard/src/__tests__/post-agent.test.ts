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

import * as childProcess from 'node:child_process'
import * as p from '@clack/prompts'

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
    fs.writeFileSync(
      path.join(cwd, 'drizzle', '0001_encrypt.sql'),
      'ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search;\n',
    )

    await runDrizzle()

    const [options] = vi.mocked(p.confirm).mock.calls.at(-1) ?? []
    expect(options?.initialValue).toBe(false)
    expect(String(options?.message)).toContain('DESTROYS data')
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
  })
})
