import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CliExit } from '@/cli/exit.js'
import { EqlReinstallRefusalError } from '@/installer/derived-search-index-restoration.js'

const install = vi.fn()
const spinner = { start: vi.fn(), stop: vi.fn() }

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  spinner: () => spinner,
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: () => 'pnpm',
  runnerCommand: (_pm: string, command: string) => command,
}))
vi.mock('@/config/database-url.js', () => ({
  resolveDatabaseUrl: ({ databaseUrlFlag }: { databaseUrlFlag?: string }) =>
    databaseUrlFlag ?? 'postgres://test',
}))
vi.mock('@/config/index.js', () => ({
  findConfigFile: () => null,
  loadStashConfig: vi.fn(),
}))
vi.mock('../client-scaffold.js', () => ({ ensureEncryptionClient: vi.fn() }))
vi.mock('../config-scaffold.js', () => ({ offerStashConfig: vi.fn() }))
vi.mock('../grants-report.js', () => ({
  reportSupabaseGrantsOutcome: vi.fn(),
}))
vi.mock('@/installer/index.js', () => ({
  EQLInstaller: class {
    install = install
  },
}))
vi.mock('@/installer/installation-state.js', () => ({
  assessEqlInstallation: () =>
    Promise.resolve({
      v3: { status: 'absent' },
      capabilities: {
        status: 'assessed',
        preflight: {
          ok: true,
          currentUser: 'installer',
          isSuperuser: true,
          memberOfPostgres: false,
          missing: [],
        },
      },
    }),
}))
vi.mock('../detect.js', () => ({
  detectPrismaNext: () => null,
  detectSupabase: () => false,
}))

describe('installCommand', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders a reinstall refusal as an expected command failure', async () => {
    const refusal = new EqlReinstallRefusalError('reinstall refused')
    install.mockRejectedValueOnce(refusal)

    const { installCommand } = await import('../install.js')
    await expect(
      installCommand({
        databaseUrl: 'postgres://test',
        force: true,
        scaffoldConfig: 'skip',
      }),
    ).rejects.toEqual(new CliExit(1))

    expect(spinner.stop).toHaveBeenLastCalledWith('EQL installation failed.')
    expect(
      vi.mocked((await import('@clack/prompts')).log.error),
    ).toHaveBeenCalledWith('reinstall refused')
  })

  it('preserves an unexpected install error', async () => {
    const error = new Error('database disappeared')
    install.mockRejectedValueOnce(error)

    const { installCommand } = await import('../install.js')
    await expect(
      installCommand({
        databaseUrl: 'postgres://test',
        force: true,
        scaffoldConfig: 'skip',
      }),
    ).rejects.toBe(error)
  })
})
