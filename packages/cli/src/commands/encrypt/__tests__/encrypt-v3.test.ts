import { beforeEach, describe, expect, it, vi } from 'vitest'

// The EQL-v3 lifecycle branches (#648/#649): v3 has no cut-over rename —
// `encrypt cutover` must short-circuit with guidance instead of running the
// v2 config machine, and `encrypt drop` must target the ORIGINAL plaintext
// column (there is no `<col>_plaintext`) gated on `backfilled` AND a live
// coverage check. Version + encrypted-column NAME come from the domain types
// via `resolveEncryptedColumn` — the `<col>_encrypted` naming is a
// convention, never relied upon. The v2 paths are pinned alongside as
// regression guards.

const queryMock = vi.hoisted(() =>
  vi.fn(async (_sql: string) => ({ rows: [] as unknown[] })),
)
vi.mock('pg', () => ({
  default: {
    Client: class {
      connect = vi.fn(async () => {})
      end = vi.fn(async () => {})
      query = queryMock
    },
  },
}))

type ColumnInfo = { column: string; domain: string; version: 2 | 3 }

const migrateMocks = vi.hoisted(() => ({
  resolveEncryptedColumn: vi.fn(
    async (): Promise<ColumnInfo | null> => ({
      column: 'email_encrypted',
      domain: 'eql_v3_text_search',
      version: 3,
    }),
  ),
  listEncryptedColumns: vi.fn(async (): Promise<ColumnInfo[]> => []),
  readManifest: vi.fn(async () => null),
  countUnencrypted: vi.fn(async () => 0),
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

const V3_INFO: ColumnInfo = {
  column: 'email_encrypted',
  domain: 'eql_v3_text_search',
  version: 3,
}
const V3_CUSTOM_INFO: ColumnInfo = {
  column: 'email_enc',
  domain: 'eql_v3_text_search',
  version: 3,
}
const V2_INFO: ColumnInfo = {
  column: 'email_encrypted',
  domain: 'eql_v2_encrypted',
  version: 2,
}

/** v2 config machine present + a pending config row. */
function mockV2ConfigQueries() {
  queryMock.mockImplementation(async (sql: string) => {
    if (typeof sql !== 'string') return { rows: [] }
    if (sql.includes('to_regclass')) {
      return { rows: [{ exists: 'eql_v2_configuration' }] }
    }
    if (sql.includes('eql_v2_configuration')) {
      return { rows: [{ exists: true }] }
    }
    return { rows: [] }
  })
}

function spyExit() {
  return vi
    .spyOn(process, 'exit')
    .mockImplementation((() => undefined) as never)
}

describe('encrypt cutover — EQL version awareness', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    queryMock.mockResolvedValue({ rows: [] })
    migrateMocks.progress.mockResolvedValue({ phase: 'backfilled' })
    migrateMocks.resolveEncryptedColumn.mockResolvedValue(V3_INFO)
  })

  it('short-circuits on a backfilled v3 column: guidance, no rename, no config machine, exit 0', async () => {
    const exitSpy = spyExit()

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
    expect(exitSpy).not.toHaveBeenCalled()
    exitSpy.mockRestore()
  })

  it('v3 mid-backfill: does NOT tell the user to switch; exits 1', async () => {
    migrateMocks.progress.mockResolvedValue({ phase: 'dual-writing' })
    const exitSpy = spyExit()

    await cutoverCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining("hasn't finished backfilling"),
    )
    // The switch-now guidance must not appear before backfill completes —
    // following it mid-backfill reads NULLs for unbackfilled rows.
    expect(p.log.info).not.toHaveBeenCalledWith(
      expect.stringContaining('point your application'),
    )
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('uses the RESOLVED encrypted column name, not the naming convention', async () => {
    migrateMocks.resolveEncryptedColumn.mockResolvedValue(V3_CUSTOM_INFO)

    await cutoverCommand({ table: 'users', column: 'email' })

    expect(p.log.info).toHaveBeenCalledWith(
      expect.stringContaining('email_enc'),
    )
    expect(p.log.info).not.toHaveBeenCalledWith(
      expect.stringContaining('email_encrypted'),
    )
  })

  it('still runs the v2 flow for a v2 column (regression pin)', async () => {
    migrateMocks.resolveEncryptedColumn.mockResolvedValue(V2_INFO)
    mockV2ConfigQueries()

    await cutoverCommand({ table: 'users', column: 'email' })

    expect(migrateMocks.renameEncryptedColumns).toHaveBeenCalled()
    expect(migrateMocks.migrateConfig).toHaveBeenCalled()
    expect(migrateMocks.activateConfig).toHaveBeenCalled()
  })

  it('explains a v3-only database instead of a raw relation-does-not-exist error', async () => {
    // Detection missed (e.g. no EQL columns visible) → v2 path — but the
    // config table doesn't exist on this database.
    migrateMocks.resolveEncryptedColumn.mockResolvedValue(null)
    migrateMocks.listEncryptedColumns.mockResolvedValue([])
    queryMock.mockImplementation(async (sql: string) =>
      typeof sql === 'string' && sql.includes('to_regclass')
        ? { rows: [{ exists: null }] }
        : { rows: [] },
    )
    const exitSpy = spyExit()

    await cutoverCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('no EQL v2 configuration table'),
    )
    expect(migrateMocks.renameEncryptedColumns).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })
})

describe('encrypt drop — EQL version awareness', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    queryMock.mockResolvedValue({ rows: [] })
    migrateMocks.resolveEncryptedColumn.mockResolvedValue(V3_INFO)
    migrateMocks.countUnencrypted.mockResolvedValue(0)
  })

  it('v3: requires phase backfilled, verifies coverage, and drops the ORIGINAL column', async () => {
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilled' })

    await dropCommand({ table: 'users', column: 'email' })

    // The coverage gate ran against the RESOLVED encrypted column.
    expect(migrateMocks.countUnencrypted).toHaveBeenCalledWith(
      expect.anything(),
      'users',
      'email',
      'email_encrypted',
    )
    // Non-drizzle fallback writes the SQL file — inspect the generated DDL.
    const sql = writeFileMock.mock.calls[0]?.[1] as string
    expect(sql).toContain('DROP COLUMN "email"')
    expect(sql).not.toContain('email_plaintext')
    expect(migrateMocks.appendEvent).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ event: 'dropped', phase: 'dropped' }),
    )
  })

  it('v3: refuses to generate when rows are still plaintext-only', async () => {
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilled' })
    migrateMocks.countUnencrypted.mockResolvedValueOnce(7)
    const exitSpy = spyExit()

    await dropCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('7 row(s)'),
    )
    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('stash encrypt backfill'),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(migrateMocks.appendEvent).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('v3: gates coverage on the RESOLVED encrypted column name', async () => {
    migrateMocks.resolveEncryptedColumn.mockResolvedValue(V3_CUSTOM_INFO)
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilled' })

    await dropCommand({ table: 'users', column: 'email' })

    expect(migrateMocks.countUnencrypted).toHaveBeenCalledWith(
      expect.anything(),
      'users',
      'email',
      'email_enc',
    )
    const sql = writeFileMock.mock.calls[0]?.[1] as string
    expect(sql).toContain('DROP COLUMN "email"')
  })

  it('v3: rejects when not yet backfilled', async () => {
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilling' })
    const exitSpy = spyExit()

    await dropCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining("Must be 'backfilled'"),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('v2: unchanged — requires cut-over, no coverage gate, drops <col>_plaintext (regression pin)', async () => {
    migrateMocks.resolveEncryptedColumn.mockResolvedValue(V2_INFO)
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'cut-over' })

    await dropCommand({ table: 'users', column: 'email' })

    const sql = writeFileMock.mock.calls[0]?.[1] as string
    expect(sql).toContain('DROP COLUMN "email_plaintext"')
    expect(migrateMocks.countUnencrypted).not.toHaveBeenCalled()
  })
})
