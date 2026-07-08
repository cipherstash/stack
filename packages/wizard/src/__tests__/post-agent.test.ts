import { beforeEach, describe, expect, it, vi } from 'vitest'
import { runPostAgentSteps } from '../lib/post-agent.js'
import type { DetectedPackageManager } from '../lib/types.js'

// Mock the child_process module
vi.mock('node:child_process')

import * as childProcess from 'node:child_process'

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

  it('executes db install/db push using the detected runner (bun → bunx) when usesProxy=true', async () => {
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

  it('skips db install when hasStashConfig=true and still uses bunx for db push when usesProxy=true', async () => {
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
