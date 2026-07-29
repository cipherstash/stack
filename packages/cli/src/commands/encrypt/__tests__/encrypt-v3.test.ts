import type {
  EncryptedColumnInfo,
  ResolvedEncryptedColumn,
} from '@cipherstash/migrate'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ResolvedLifecycle } from '../lib/resolve-eql.js'

// The EQL-v3 drop lifecycle (#649): `encrypt drop` must target the ORIGINAL
// plaintext column (there is no `<col>_plaintext`) gated on `backfilled` AND a live
// coverage check. Version + encrypted-column NAME come from the domain types
// via `resolveColumnLifecycle` — the `<col>_encrypted` naming is a
// convention, never relied upon — and both commands FAIL CLOSED when
// resolution is ambiguous instead of guessing a lifecycle. The v2 paths are
// pinned alongside as regression guards.

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

// Imported, never re-declared. These stubs stand in for the real
// `resolveColumnLifecycle`, so a structural copy would let a renamed or added
// field compile on both sides while the commands read something the resolver no
// longer returns — the exact seam `v2-lifecycle-composition.integration.test.ts`
// exercises at runtime, pinned here at compile time (#787 review follow-up).
type ColumnInfo = EncryptedColumnInfo
type ResolvedInfo = ResolvedEncryptedColumn
type Lifecycle = ResolvedLifecycle

const migrateMocks = vi.hoisted(() => ({
  listEncryptedColumns: vi.fn(async (): Promise<ColumnInfo[]> => []),
  pickEncryptedColumn: vi.fn(() => null),
  readManifest: vi.fn(async () => null),
  countUnencrypted: vi.fn(async () => 0),
  progress: vi.fn(
    async () => ({ phase: 'backfilled' }) as { phase: string } | null,
  ),
  appendEvent: vi.fn(async () => {}),
  setManifestTargetPhase: vi.fn(async () => {}),
  quoteIdent: (identifier: string) => `"${identifier.replace(/"/g, '""')}"`,
  qualifyTable: (table: string) =>
    table
      .split('.')
      .map((part) => `"${part.replace(/"/g, '""')}"`)
      .join('.'),
}))
vi.mock('@cipherstash/migrate', () => migrateMocks)

// Mock the lifecycle RESOLUTION (each test states its scenario directly)
// but keep the real `explainUnresolved` — the fail-closed messaging is part
// of what these tests pin.
const lifecycleMock = vi.hoisted(() =>
  vi.fn(
    async (): Promise<{
      info: (ColumnInfo & { via: string }) | null
      candidates: ColumnInfo[]
    }> => ({ info: null, candidates: [] }),
  ),
)
vi.mock('../lib/resolve-eql.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/resolve-eql.js')>()
  return { ...actual, resolveColumnLifecycle: lifecycleMock }
})

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
function resolved(
  info: ColumnInfo,
  via: ResolvedInfo['via'] = 'convention',
): Lifecycle {
  return { info: { ...info, via }, candidates: [info] }
}

function spyExit() {
  return vi
    .spyOn(process, 'exit')
    .mockImplementation((() => undefined) as never)
}

describe('encrypt drop — EQL version awareness', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    queryMock.mockResolvedValue({ rows: [] })
    lifecycleMock.mockResolvedValue(resolved(V3_INFO))
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

  it('v3: the generated migration re-verifies coverage at APPLY time, atomically', async () => {
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilled' })

    await dropCommand({ table: 'users', column: 'email' })

    // The CLI-side count goes stale the moment the file is written; the
    // migration must lock, re-count, and abort without dropping if any
    // plaintext-only row appeared between generation and application.
    const sql = writeFileMock.mock.calls[0]?.[1] as string
    expect(sql).toContain('LOCK TABLE "users" IN ACCESS EXCLUSIVE MODE')
    expect(sql).toContain('RAISE EXCEPTION')
    expect(sql).toContain('"email" IS NOT NULL')
    expect(sql).toContain('"email_encrypted" IS NULL')
    // The DROP itself runs inside the same DO block (EXECUTE), so
    // check-and-drop stay atomic even under non-transactional runners.
    expect(sql).toMatch(/EXECUTE 'ALTER TABLE "users" DROP COLUMN "email"'/)
  })

  it('quotes unusual identifiers and sanitizes the migration filename', async () => {
    lifecycleMock.mockResolvedValue(
      resolved(
        {
          column: 'email"encrypted',
          domain: 'eql_v3_text_search',
          version: 3,
        },
        'hint',
      ),
    )
    migrateMocks.progress.mockResolvedValueOnce({ phase: 'backfilled' })

    await dropCommand({
      table: 'tenant.weird"table',
      column: '../email"',
    })

    const [filePath, sql] = writeFileMock.mock.calls[0] as [string, string]
    expect(sql).toContain('LOCK TABLE "tenant"."weird""table"')
    expect(sql).toContain('"../email""" IS NOT NULL')
    expect(sql).toContain('"email""encrypted" IS NULL')
    expect(filePath).toMatch(/_drop_tenant_weird_table_email\.sql$/)
    expect(filePath).not.toContain('../email')
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
    lifecycleMock.mockResolvedValue(resolved(V3_CUSTOM_INFO, 'hint'))
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

  it("v3: refuses a by-elimination ('sole') match — uniqueness cannot prove the pairing", async () => {
    // The table's ONE EQL column may encrypt a DIFFERENT field; gating
    // coverage on it and dropping `email` could destroy the only copy.
    lifecycleMock.mockResolvedValue(
      resolved(
        { column: 'secret_blob', domain: 'eql_v3_text_search', version: 3 },
        'sole',
      ),
    )
    // No progress stub: the sole-match guard fires before the phase gate
    // ever consults cs_migrations. (Queuing an unconsumed
    // mockResolvedValueOnce here would leak into the next test.)
    const exitSpy = spyExit()

    await dropCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('nothing confirms it encrypts "email"'),
    )
    // The remedy must not prescribe the GUESS. Recording `secret_blob` makes
    // the next resolution `via: 'hint'`, which walks past this very gate — and
    // the coverage check then passes vacuously, because an unrelated but
    // legitimately-backfilled column is non-NULL on every row. Following that
    // advice generated a live DROP COLUMN on the plaintext at exit 0
    // (#772 review, finding 7).
    expect(p.log.error).not.toHaveBeenCalledWith(
      expect.stringContaining('--encrypted-column secret_blob'),
    )
    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('--encrypted-column <name>'),
    )
    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('do not record secret_blob'),
    )
    expect(migrateMocks.countUnencrypted).not.toHaveBeenCalled()
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('fails closed when EQL columns exist but none is identifiable', async () => {
    lifecycleMock.mockResolvedValue({
      info: null,
      candidates: [
        { column: 'a_enc', domain: 'eql_v3_text_eq', version: 3 },
        { column: 'b_enc', domain: 'eql_v3_text_eq', version: 3 },
      ],
    })
    const exitSpy = spyExit()

    await dropCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('Cannot identify which encrypted column'),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
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

  it('rejects an unclassified legacy column instead of taking a v2 drop path', async () => {
    lifecycleMock.mockResolvedValue({ info: null, candidates: [] })
    const exitSpy = spyExit()

    await dropCommand({ table: 'users', column: 'email' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining(
        'Legacy EQL v2 drop/cut-over automation has been removed',
      ),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })
})
