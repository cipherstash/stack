import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

const execSyncMock = vi.hoisted(() => vi.fn())
vi.mock('node:child_process', () => ({ execSync: execSyncMock }))
// Collaborators from utils — control install state + commands without a real PM.
vi.mock('../../utils.js', () => ({
  isPackageInstalled: vi.fn(() => false),
  installedVersion: vi.fn(() => undefined),
  combinedInstallCommands: vi.fn(
    (_pm: string, prod: string[], dev: string[]) => [
      ...(prod.length ? [`npm install ${prod.join(' ')}`] : []),
      ...(dev.length ? [`npm install --save-dev ${dev.join(' ')}`] : []),
    ],
  ),
  detectPackageManager: vi.fn(() => 'npm'),
}))
// Pin map: pretend this CLI release was built alongside these versions, so
// the pinned-spec and skew paths are exercisable from source-mode tests
// (where the real build-time embed is absent).
vi.mock('../../../../runtime-versions.js', () => {
  const versions: Record<string, string> = {
    stash: '1.0.0-rc.2',
    '@cipherstash/stack': '1.0.0-rc.2',
    '@cipherstash/stack-supabase': '1.0.0-rc.2',
  }
  return {
    expectedVersion: (pkg: string) => versions[pkg],
    pinnedSpec: (pkg: string) =>
      versions[pkg] ? `${pkg}@${versions[pkg]}` : pkg,
  }
})
// Toggle interactivity per test (defaults to interactive in beforeEach).
vi.mock('../../../../config/tty.js', () => ({
  isInteractive: vi.fn(() => true),
}))
vi.mock('@clack/prompts', () => ({
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: {
    info: vi.fn(),
    success: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    step: vi.fn(),
  },
  note: vi.fn(),
}))

import * as p from '@clack/prompts'
import { isInteractive } from '../../../../config/tty.js'
import {
  combinedInstallCommands,
  installedVersion,
  isPackageInstalled,
} from '../../utils.js'
import { installDepsStep, versionSkew } from '../install-deps.js'

const baseState = {} as unknown as InitState
const provider = { name: 'postgresql' } as unknown as InitProvider

describe('installDepsStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(isInteractive).mockReturnValue(true)
    vi.mocked(isPackageInstalled).mockReturnValue(false)
  })

  it('prompts before installing when interactive', async () => {
    // Missing at the gate, present on the post-install recheck.
    let n = 0
    vi.mocked(isPackageInstalled).mockImplementation(() => ++n > 2)

    await installDepsStep.run(baseState, provider)

    expect(p.confirm).toHaveBeenCalledTimes(1)
    expect(execSyncMock).toHaveBeenCalled()
  })

  it('installs without prompting when non-interactive (#600)', async () => {
    vi.mocked(isInteractive).mockReturnValue(false)
    let n = 0
    vi.mocked(isPackageInstalled).mockImplementation(() => ++n > 2)

    await installDepsStep.run(baseState, provider)

    // No TTY to answer the prompt; init installs by default instead of aborting.
    expect(p.confirm).not.toHaveBeenCalled()
    expect(execSyncMock).toHaveBeenCalled()
  })

  it('skips silently when everything is already installed (no prompt)', async () => {
    vi.mocked(isPackageInstalled).mockReturnValue(true)

    const result = await installDepsStep.run(baseState, provider)

    expect(p.confirm).not.toHaveBeenCalled()
    expect(execSyncMock).not.toHaveBeenCalled()
    expect(result.stackInstalled).toBe(true)
    expect(result.cliInstalled).toBe(true)
  })

  it('pins fresh installs to the versions this release was built with (#661)', async () => {
    // Missing at the gate, present on the post-install recheck.
    let n = 0
    vi.mocked(isPackageInstalled).mockImplementation(() => ++n > 3)

    await installDepsStep.run(baseState, {
      name: 'supabase',
    } as unknown as InitProvider)

    const [, prod, dev] = vi.mocked(combinedInstallCommands).mock.calls[0]
    expect(prod).toEqual([
      '@cipherstash/stack@1.0.0-rc.2',
      '@cipherstash/stack-supabase@1.0.0-rc.2',
    ])
    expect(dev).toEqual(['stash@1.0.0-rc.2'])
  })

  it('warns on version skew when packages are already installed (#661)', async () => {
    vi.mocked(isPackageInstalled).mockReturnValue(true)
    // The dist-tag failure mode: node_modules holds the stale 0.19.0.
    vi.mocked(installedVersion).mockImplementation((pkg: string) =>
      pkg === '@cipherstash/stack' ? '0.19.0' : '1.0.0-rc.2',
    )

    await installDepsStep.run(baseState, provider)

    expect(execSyncMock).not.toHaveBeenCalled()
    expect(p.log.warn).toHaveBeenCalledWith(
      expect.stringContaining(
        '@cipherstash/stack: installed 0.19.0, this release of stash expects 1.0.0-rc.2',
      ),
    )
  })

  it('stays silent when installed versions match the release', async () => {
    vi.mocked(isPackageInstalled).mockReturnValue(true)
    vi.mocked(installedVersion).mockReturnValue('1.0.0-rc.2')

    await installDepsStep.run(baseState, provider)

    expect(p.log.warn).not.toHaveBeenCalled()
  })

  describe('versionSkew', () => {
    it('reports only packages whose resolved version differs', () => {
      vi.mocked(installedVersion).mockImplementation((pkg: string) =>
        pkg === '@cipherstash/stack' ? '0.19.0' : '1.0.0-rc.2',
      )
      expect(
        versionSkew(['@cipherstash/stack', 'stash'], {
          '@cipherstash/stack': '1.0.0-rc.2',
          stash: '1.0.0-rc.2',
        }),
      ).toEqual([
        {
          pkg: '@cipherstash/stack',
          installed: '0.19.0',
          expected: '1.0.0-rc.2',
        },
      ])
    })

    it('reports nothing for absent packages or an absent release map', () => {
      vi.mocked(installedVersion).mockReturnValue(undefined)
      expect(
        versionSkew(['@cipherstash/stack'], {
          '@cipherstash/stack': '1.0.0-rc.2',
        }),
      ).toEqual([])
      vi.mocked(installedVersion).mockReturnValue('0.19.0')
      expect(versionSkew(['@no-map/package'], {})).toEqual([])
    })
  })
})
