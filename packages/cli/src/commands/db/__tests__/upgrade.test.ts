import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CliExit } from '@/cli/exit.js'
import { EqlReinstallRefusalError } from '@/installer/derived-search-index-restoration.js'

const assess = vi.fn()
const install = vi.fn()
const logInfo = vi.fn()
const logError = vi.fn()
const spinner = { start: vi.fn(), stop: vi.fn() }

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  spinner: () => spinner,
  log: { info: logInfo, warn: vi.fn(), error: logError },
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
vi.mock('@/installer/index.js', () => ({
  EQLInstaller: class {
    install = install
  },
}))

describe('upgradeCommand version reporting', () => {
  beforeEach(() => vi.clearAllMocks())

  it('does not call two unknown versions unchanged', async () => {
    assess.mockResolvedValue({
      v3: { status: 'installed', version: 'unknown' },
    })
    install.mockResolvedValue({ deferredGrantsSql: null })

    const { upgradeCommand } = await import('../upgrade.js')
    await upgradeCommand({})

    expect(logInfo).not.toHaveBeenCalledWith(
      'Version unchanged — EQL was already up to date.',
    )
  })

  it('renders a reinstall refusal as an expected command failure', async () => {
    assess.mockResolvedValue({
      v3: { status: 'installed', version: '3.0.4' },
    })
    install.mockRejectedValue(new EqlReinstallRefusalError('reinstall refused'))

    const { upgradeCommand } = await import('../upgrade.js')
    await expect(upgradeCommand({})).rejects.toEqual(new CliExit(1))

    expect(spinner.stop).toHaveBeenLastCalledWith('EQL upgrade failed.')
    expect(logError).toHaveBeenCalledWith('reinstall refused')
  })

  it('preserves an unexpected upgrade error', async () => {
    assess.mockResolvedValue({
      v3: { status: 'installed', version: '3.0.4' },
    })
    const error = new Error('database disappeared')
    install.mockRejectedValue(error)

    const { upgradeCommand } = await import('../upgrade.js')
    await expect(upgradeCommand({})).rejects.toBe(error)
  })
})
