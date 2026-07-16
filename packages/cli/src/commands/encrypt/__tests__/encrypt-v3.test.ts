import { beforeEach, describe, expect, it, vi } from 'vitest'

// The EQL-v3 lifecycle branches (#648/#649): v3 has no cut-over rename —
// `encrypt cutover` must short-circuit with guidance instead of running the
// v2 config machine, and `encrypt drop` must target the ORIGINAL plaintext
// column (there is no `<col>_plaintext`) gated on `backfilled` rather than
// `cut-over`. The v2 paths are pinned alongside as regression guards.

const queryMock = vi.hoisted(() => vi.fn(async () => ({ rows: [] })))
vi.mock('pg', () => ({
  default: {
    Client: class {
      connect = vi.fn(async () => {})
      end = vi.fn(async () => {})
      query = queryMock
    },
  },
}))

const migrateMocks = vi.hoisted(() => ({
  detectColumnEqlVersion: vi.fn(async () => 'v3' as 'v2' | 'v3' | null),
  progress: vi.fn(
    async () => ({ phase: 'backfilled' }) as { phase: string } | null,
  ),
  appendEvent: vi.fn(async () => {}),
  setManifestTargetPhase: vi.fn(async () => {}),
  renameEncryptedColumns: vi.fn(async () => {}),
  migrateConfig: vi.fn(async () => {}),
  activateConfig: vi.fn(async () => {}),
  reloadConfig: vi.fn(async () => {}),
}))
vi.mock('@cipherstash/migrate', () => migrateMocks)

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
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
vi.mock('@/config/index.js', () => ({
  loadStashConfig: vi.fn(async () => ({ databaseUrl: 'postgres://test' })),
}))
vi.mock('@/commands/db/detect.js', () => ({
  detectDrizzle: vi.fn(() => false),
}))
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: vi.fn(() => 'npm'),
  runnerCommand: vi.fn((_pm: string, ref: string) => `npx ${ref}`),
}))
const scaffoldMock = vi.hoisted(() =>
  vi.fn(async ({ name }: { name: string }) => ({
    path: `drizzle/${name}.sql`,
  })),
)
vi.mock('../drizzle-helper.js', () => ({
  scaffoldDrizzleMigration: scaffoldMock,
}))
const writeFileMock = vi.hoisted(() => vi.fn())
vi.mock('node:fs', () => ({
  default: { mkdirSync: vi.fn(), writeFileSync: writeFileMock },
}))

import * as p from '@clack/prompts'
import { cutoverCommand } from '../cutover.js'
import { dropCommand } from '../drop.js'

describe('encrypt cutover — EQL version awareness', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    migrateMocks.progress.mockResolvedValue({ phase: 'backfilled' })
  })

  it('short-circuits on a v3 column: guidance, no rename, no config machine', async () => {
    migrateMocks.detectColumnEqlVersion.mockResolvedValueOnce('v3')

    await cutoverCommand({ table: 'users', column: 'email' })

    expect(p.log.info).toHaveBeenCalledWith(
      expect.stringContaining('not applicable to EQL v3'),
    )
    expect(p.log.info).toHaveBeenCalledWith(
      expect.stringContaining('stash encrypt drop'),
    )
    expect(migrateMocks.renameEncryptedColumns).not.toHaveBeenCalled()
    expect(migrateMocks.migrateConfig).not.toHaveBeenCalled()
    expect(migrateMocks.activateConfig).not.toHaveBeenCalled()
    expect(migrateMocks.appendEvent).not.toHaveBeenCalled()
  })

  it('still runs the v2 flow for a v2 column (regression pin)', async () => {
    migrateMocks.detectColumnEqlVersion.mockResolvedValueOnce('v2')
    // pending-config check returns true
    queryMock.mockImplementation(async (sql: string) =>
      typeof sql === 'string' && sql.includes('eql_v2_configuration')
        ? { rows: [{ exists: true }] }
        : { rows: [] },
    )

    await cutoverCommand({ table: 'users', column: 'email' })

    expect(migrateMocks.renameEncryptedColumns).toHaveBeenCalled()
    expect(migrateMocks.migrateConfig).toHaveBeenCalled()
    expect(migrateMocks.activateConfig).toHaveBeenCalled()
  })
})

describe('encrypt drop — EQL version awareness', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('v3: requires phase backfilled and drops the ORIGINAL column', async () => {
    migrateMocks.detectColumnEqlVersion.mockResolvedValueOnce('v3')
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilled' })

    await dropCommand({ table: 'users', column: 'email' })

    // Non-drizzle fallback writes the SQL file — inspect the generated DDL.
    const sql = writeFileMock.mock.calls[0]?.[1] as string
    expect(sql).toContain('DROP COLUMN "email"')
    expect(sql).not.toContain('email_plaintext')
    expect(migrateMocks.appendEvent).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ event: 'dropped', phase: 'dropped' }),
    )
  })

  it('v3: rejects when not yet backfilled', async () => {
    migrateMocks.detectColumnEqlVersion.mockResolvedValueOnce('v3')
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilling' })
    const exitSpy = vi
      .spyOn(process, 'exit')
      .mockImplementation((() => undefined) as never)

    await dropCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining("Must be 'backfilled'"),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('v2: unchanged — requires cut-over and drops <col>_plaintext (regression pin)', async () => {
    migrateMocks.detectColumnEqlVersion.mockResolvedValueOnce('v2')
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'cut-over' })

    await dropCommand({ table: 'users', column: 'email' })

    const sql = writeFileMock.mock.calls[0]?.[1] as string
    expect(sql).toContain('DROP COLUMN "email_plaintext"')
  })
})
