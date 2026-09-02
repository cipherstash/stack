import { beforeEach, describe, expect, it, vi } from 'vitest'

const assess = vi.fn()
const logError = vi.fn()
const logInfo = vi.fn()
const spinner = { start: vi.fn(), stop: vi.fn() }

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  spinner: () => spinner,
  log: { error: logError, info: logInfo, success: vi.fn(), warn: vi.fn() },
}))
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: () => 'pnpm',
  runnerCommand: (_pm: string, command: string) => command,
}))
vi.mock('@/config/index.js', () => ({
  loadStashConfig: () => ({ databaseUrl: 'postgres://test' }),
}))
vi.mock('@/installer/installation-state.js', () => ({
  assessEqlInstallation: assess,
}))

describe('statusCommand advisory sections', () => {
  beforeEach(() => vi.clearAllMocks())

  it('continues to ORE when the independent permission assessment fails', async () => {
    assess
      .mockResolvedValueOnce({
        v2: { status: 'absent' },
        v3: { status: 'installed', version: '3.0.5' },
        capabilities: { status: 'not-requested' },
        ore: {
          status: 'observed',
          state: 'indexable',
          opclassPresent: true,
          poisonedDomains: 0,
          expectedPoisoned: 20,
        },
        surface: { status: 'not-requested' },
      })
      .mockRejectedValueOnce(new Error('permission probe failed'))

    const { statusCommand } = await import('../status.js')
    await statusCommand()

    expect(assess).toHaveBeenCalledTimes(2)
    expect(logError).toHaveBeenCalledWith('permission probe failed')
    expect(logInfo).toHaveBeenCalledWith(expect.stringContaining('usable'))
  })
})
