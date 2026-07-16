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
// (where the real build-time embed is absent). The versions are arbitrary
// FIXTURES (deliberately unreal, so nobody mistakes them for values that must
// track a release) — production values come from the workspace manifests at
// build time, never from constants.
const FIXTURE_VERSIONS: Record<string, string> = vi.hoisted(() => ({
  stash: '9.9.9-test.1',
  '@cipherstash/stack': '9.9.9-test.1',
  '@cipherstash/stack-supabase': '9.9.9-test.1',
}))
vi.mock('../../../../runtime-versions.js', async (importOriginal) => ({
  // Keep the real pure helpers (compareVersions, parseEmbeddedVersions);
  // override only the release map and the map-reading functions.
  ...(await importOriginal<typeof import('../../../../runtime-versions.js')>()),
  RUNTIME_PACKAGE_VERSIONS: FIXTURE_VERSIONS,
  expectedVersion: (
    pkg: string,
    versions: Record<string, string> = FIXTURE_VERSIONS,
  ): string | undefined => versions[pkg],
  pinnedSpec: (
    pkg: string,
    versions: Record<string, string> = FIXTURE_VERSIONS,
  ): string => (versions[pkg] ? `${pkg}@${versions[pkg]}` : pkg),
}))
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
const supabaseProvider = { name: 'supabase' } as unknown as InitProvider

/** Presence by package name — clearer and more robust than call counters. */
function present(...pkgs: string[]) {
  vi.mocked(isPackageInstalled).mockImplementation((pkg: string) =>
    pkgs.includes(pkg),
  )
}

/** Resolved on-disk versions by package name. */
function resolvedVersions(map: Record<string, string | undefined>) {
  vi.mocked(installedVersion).mockImplementation((pkg: string) => map[pkg])
}

/** The combinedInstallCommands call that actually built install commands
 * (skips the always-made align-commands call, which may have empty lists). */
function installCall(): [string, string[], string[]] {
  const calls = vi.mocked(combinedInstallCommands).mock.calls as Array<
    [string, string[], string[]]
  >
  const nonEmpty = calls.filter(([, prod, dev]) => prod.length + dev.length > 0)
  expect(nonEmpty.length).toBeGreaterThan(0)
  return nonEmpty[nonEmpty.length - 1]
}

describe('installDepsStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(isInteractive).mockReturnValue(true)
    present() // nothing installed
    resolvedVersions({})
  })

  it('prompts before installing when interactive', async () => {
    // Missing at the gate, present on the post-install recheck.
    let installed = false
    vi.mocked(isPackageInstalled).mockImplementation(() => installed)
    execSyncMock.mockImplementation(() => {
      installed = true
      return ''
    })

    await installDepsStep.run(baseState, provider)

    expect(p.confirm).toHaveBeenCalledTimes(1)
    expect(execSyncMock).toHaveBeenCalled()
  })

  it('installs without prompting when non-interactive (#600)', async () => {
    vi.mocked(isInteractive).mockReturnValue(false)

    await installDepsStep.run(baseState, provider)

    // No TTY to answer the prompt; init installs by default instead of aborting.
    expect(p.confirm).not.toHaveBeenCalled()
    expect(execSyncMock).toHaveBeenCalled()
  })

  it('skips silently when everything is installed at matching versions', async () => {
    present('@cipherstash/stack', 'stash')
    resolvedVersions({
      '@cipherstash/stack': FIXTURE_VERSIONS['@cipherstash/stack'],
      stash: FIXTURE_VERSIONS.stash,
    })

    const result = await installDepsStep.run(baseState, provider)

    expect(p.confirm).not.toHaveBeenCalled()
    expect(execSyncMock).not.toHaveBeenCalled()
    expect(p.log.warn).not.toHaveBeenCalled()
    expect(result.stackInstalled).toBe(true)
    expect(result.cliInstalled).toBe(true)
  })

  it('pins fresh installs to the versions this release was built with (#661)', async () => {
    await installDepsStep.run(baseState, supabaseProvider)

    const [, prod, dev] = installCall()
    expect(prod).toEqual([
      '@cipherstash/stack@9.9.9-test.1',
      '@cipherstash/stack-supabase@9.9.9-test.1',
    ])
    expect(dev).toEqual(['stash@9.9.9-test.1'])
  })

  it('warns on version skew and aligns with the dev/prod split intact (#661)', async () => {
    // The dist-tag failure mode: node_modules holds stale versions of both
    // the runtime package (prod) and the CLI (dev).
    present('@cipherstash/stack', 'stash')
    resolvedVersions({ '@cipherstash/stack': '0.19.0', stash: '0.19.0' })

    await installDepsStep.run(baseState, provider)

    expect(p.log.warn).toHaveBeenCalledWith(
      expect.stringContaining(
        '@cipherstash/stack: installed 0.19.0, this release of stash expects 9.9.9-test.1',
      ),
    )
    // Accepted (confirm mock defaults to true) → aligned with `stash` in the
    // DEV list, not prod: the align command must not reclassify the CLI as a
    // runtime dependency.
    const [, prod, dev] = installCall()
    expect(prod).toEqual(['@cipherstash/stack@9.9.9-test.1'])
    expect(dev).toEqual(['stash@9.9.9-test.1'])
    expect(execSyncMock).toHaveBeenCalled()
  })

  it('still warns on skew when the user declines the install', async () => {
    present('@cipherstash/stack', 'stash')
    resolvedVersions({
      '@cipherstash/stack': '0.19.0',
      stash: FIXTURE_VERSIONS.stash,
    })
    vi.mocked(p.confirm).mockResolvedValueOnce(false)

    await installDepsStep.run(baseState, provider)

    // The warning precedes the prompt, so declining cannot skip it.
    expect(p.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('@cipherstash/stack: installed 0.19.0'),
    )
    expect(execSyncMock).not.toHaveBeenCalled()
    expect(p.note).toHaveBeenCalledWith(
      expect.stringContaining('@cipherstash/stack@9.9.9-test.1'),
      'Manual Installation',
    )
  })

  it('non-interactive: warns on skew, prints align commands, never mutates', async () => {
    vi.mocked(isInteractive).mockReturnValue(false)
    present('@cipherstash/stack', 'stash')
    resolvedVersions({
      '@cipherstash/stack': '0.19.0',
      stash: FIXTURE_VERSIONS.stash,
    })

    const result = await installDepsStep.run(baseState, provider)

    expect(p.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('@cipherstash/stack: installed 0.19.0'),
    )
    // The note carries the exact pinned align command (the changeset promise).
    expect(p.note).toHaveBeenCalledWith(
      expect.stringContaining('npm install @cipherstash/stack@9.9.9-test.1'),
      'Version skew',
    )
    expect(execSyncMock).not.toHaveBeenCalled()
    expect(result.stackInstalled).toBe(true)
    expect(result.cliInstalled).toBe(true)
  })

  it('a NEWER install gets an update-stash warning, never a downgrade command', async () => {
    vi.mocked(isInteractive).mockReturnValue(false)
    present('@cipherstash/stack', 'stash')
    resolvedVersions({
      '@cipherstash/stack': '9.9.10',
      stash: FIXTURE_VERSIONS.stash,
    })

    const result = await installDepsStep.run(baseState, provider)

    expect(p.log.warn).toHaveBeenCalledWith(
      expect.stringContaining(
        '@cipherstash/stack: installed 9.9.10 is newer than this release of stash expects (9.9.9-test.1)',
      ),
    )
    // No align/downgrade guidance, no mutation, clean success.
    expect(p.note).not.toHaveBeenCalled()
    expect(execSyncMock).not.toHaveBeenCalled()
    expect(result.stackInstalled).toBe(true)
  })

  it('reports an unreadable manifest as skew, not as a matching install', async () => {
    vi.mocked(isInteractive).mockReturnValue(false)
    present('@cipherstash/stack', 'stash')
    // Aborted install: directory + manifest exist, but the manifest is
    // corrupt so installedVersion cannot read it.
    resolvedVersions({
      '@cipherstash/stack': undefined,
      stash: FIXTURE_VERSIONS.stash,
    })

    await installDepsStep.run(baseState, provider)

    expect(p.log.warn).toHaveBeenCalledWith(
      expect.stringContaining(
        '@cipherstash/stack: installed unknown (unreadable package.json)',
      ),
    )
  })
})

describe('versionSkew', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('reports only installed packages whose resolved version differs', () => {
    present('@cipherstash/stack', 'stash')
    resolvedVersions({
      '@cipherstash/stack': '0.19.0',
      stash: '9.9.9-test.1',
    })
    expect(
      versionSkew(['@cipherstash/stack', 'stash'], {
        '@cipherstash/stack': '9.9.9-test.1',
        stash: '9.9.9-test.1',
      }),
    ).toEqual([
      {
        pkg: '@cipherstash/stack',
        installed: '0.19.0',
        expected: '9.9.9-test.1',
        direction: 'behind',
      },
    ])
  })

  it('classifies a newer-than-expected install as ahead', () => {
    present('@cipherstash/stack')
    resolvedVersions({ '@cipherstash/stack': '9.9.10' })
    expect(
      versionSkew(['@cipherstash/stack'], {
        '@cipherstash/stack': '9.9.9-test.1',
      }),
    ).toEqual([
      {
        pkg: '@cipherstash/stack',
        installed: '9.9.10',
        expected: '9.9.9-test.1',
        direction: 'ahead',
      },
    ])
  })

  it('reports nothing for absent packages or packages off the release map', () => {
    present() // nothing installed
    resolvedVersions({ '@cipherstash/stack': '0.19.0' })
    expect(
      versionSkew(['@cipherstash/stack'], {
        '@cipherstash/stack': '9.9.9-test.1',
      }),
    ).toEqual([])

    present('@no-map/package')
    expect(versionSkew(['@no-map/package'], {})).toEqual([])
  })

  it('flags an installed package with an unreadable manifest', () => {
    present('@cipherstash/stack')
    resolvedVersions({ '@cipherstash/stack': undefined })
    expect(
      versionSkew(['@cipherstash/stack'], {
        '@cipherstash/stack': '9.9.9-test.1',
      }),
    ).toEqual([
      {
        pkg: '@cipherstash/stack',
        installed: 'unknown (unreadable package.json)',
        expected: '9.9.9-test.1',
        // Unreadable = broken install → offer the (re)install fix.
        direction: 'behind',
      },
    ])
  })
})
