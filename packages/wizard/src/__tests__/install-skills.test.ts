import { beforeEach, describe, expect, it, vi } from 'vitest'

// Hermetic: mock the filesystem and prompts so the tests drive the failure
// paths directly. The real-FS behaviour is covered by the `stash` CLI's copy
// of this logic (packages/cli install-skills.test.ts); this file pins the
// wizard copy's never-throw contract, which previously had no coverage —
// exactly how the original unguarded mkdirSync shipped twice (see
// cipherstash/stack#736).
vi.mock('node:fs', () => ({
  existsSync: vi.fn(() => true),
  mkdirSync: vi.fn(),
  cpSync: vi.fn(),
}))
vi.mock('@clack/prompts', () => ({
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: { warn: vi.fn(), success: vi.fn() },
}))

import { cpSync, existsSync, mkdirSync } from 'node:fs'
import * as p from '@clack/prompts'
import { maybeInstallSkills } from '../lib/install-skills.js'

const warnings = () => vi.mocked(p.log.warn).mock.calls.map(String).join('\n')

beforeEach(() => {
  // resetAllMocks (not clearAllMocks): the throwing mkdirSync implementation
  // set in one test must not leak into the next.
  vi.resetAllMocks()
  vi.mocked(existsSync).mockReturnValue(true)
  vi.mocked(p.confirm).mockResolvedValue(true)
  vi.mocked(p.isCancel).mockReturnValue(false)
})

describe('maybeInstallSkills', () => {
  it('degrades to failed (not a throw) when the destination cannot be created', async () => {
    vi.mocked(mkdirSync).mockImplementation(() => {
      throw Object.assign(new Error('EACCES: permission denied'), {
        code: 'EACCES',
      })
    })

    const result = await maybeInstallSkills('/project', 'drizzle')

    expect(result.copied).toEqual([])
    expect(result.failed).toEqual([
      'stash-encryption',
      'stash-drizzle',
      'stash-cli',
    ])
    expect(warnings()).toContain('Could not create ./.claude/skills/')
  })

  it('reports a partial copy as copied plus failed, with a warning per failure', async () => {
    vi.mocked(cpSync).mockImplementation((src) => {
      if (String(src).includes('stash-drizzle')) {
        throw Object.assign(new Error('EACCES: permission denied'), {
          code: 'EACCES',
        })
      }
    })

    const result = await maybeInstallSkills('/project', 'drizzle')

    expect(result.copied).toEqual(['stash-encryption', 'stash-cli'])
    expect(result.failed).toEqual(['stash-drizzle'])
    expect(warnings()).toContain('Failed to install skill stash-drizzle')
  })

  it('returns nothing copied and nothing failed when the user declines', async () => {
    vi.mocked(p.confirm).mockResolvedValue(false)

    const result = await maybeInstallSkills('/project', 'drizzle')

    expect(result).toEqual({ copied: [], failed: [] })
    expect(mkdirSync).not.toHaveBeenCalled()
  })
})
