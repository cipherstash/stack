import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

const execSyncMock = vi.hoisted(() => vi.fn())
vi.mock('node:child_process', () => ({ execSync: execSyncMock }))
// Collaborators from utils — control install state + commands without a real PM.
vi.mock('../../utils.js', () => ({
  isPackageInstalled: vi.fn(() => false),
  combinedInstallCommands: vi.fn(() => [
    'npm install @cipherstash/stack',
    'npm install --save-dev stash',
  ]),
  detectPackageManager: vi.fn(() => 'npm'),
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
import { isPackageInstalled } from '../../utils.js'
import { installDepsStep } from '../install-deps.js'

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
})
