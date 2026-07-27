import { beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * The seam between lifecycle RESOLUTION and the commands that act on it.
 *
 * `encrypt-v3.test.ts` stubs `resolveColumnLifecycle` and hand-writes the value
 * it returns; `resolve-eql.test.ts` separately proves a pure-v2 table produces
 * that value. Both can stay green while the shape passed between them changes,
 * because neither runs the real producer into the real consumer — and the
 * commands' v2/v3 branch is chosen entirely from that shape.
 *
 * So here `resolve-eql.js` is NOT mocked at all: `resolveColumnLifecycle`,
 * `explainUnresolved`, `pickEncryptedColumn`, `listEncryptedColumns` and
 * `columnExists` all run for real, and the pure-v2 verdict is derived from a
 * real manifest hint plus a real catalog read rather than asserted into
 * existence. Only genuine boundaries are faked: `pg`, the filesystem, prompts,
 * and the effectful migrate helpers that write to the database (#787 review
 * follow-up).
 */

const queryMock = vi.hoisted(() =>
  vi.fn(async (_sql: string, _params?: unknown[]) => ({
    rows: [] as unknown[],
  })),
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

/**
 * Spread the real module and override only the functions that TOUCH something —
 * the manifest file and the database. Everything resolution actually reasons
 * with (`listEncryptedColumns`, `columnExists`, `pickEncryptedColumn`,
 * `classifyEqlDomain`) stays real and runs against `queryMock` below.
 */
const migrateMocks = vi.hoisted(() => ({
  readManifest: vi.fn(async () => null as unknown),
  countUnencrypted: vi.fn(async () => 0),
  progress: vi.fn(
    async () => ({ phase: 'cut-over' }) as { phase: string } | null,
  ),
  appendEvent: vi.fn(async () => {}),
  setManifestTargetPhase: vi.fn(async () => {}),
  renameEncryptedColumns: vi.fn(async () => {}),
  migrateConfig: vi.fn(async () => {}),
  activateConfig: vi.fn(async () => {}),
  reloadConfig: vi.fn(async () => {}),
}))
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  ...migrateMocks,
}))

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
vi.mock('../drizzle-helper.js', () => ({
  scaffoldDrizzleMigration: vi.fn(async ({ name }: { name: string }) => ({
    path: `drizzle/${name}.sql`,
  })),
}))
const writeFileMock = vi.hoisted(() => vi.fn())
vi.mock('node:fs', () => ({
  default: { mkdirSync: vi.fn(), writeFileSync: writeFileMock },
}))

import * as p from '@clack/prompts'
import { cutoverCommand } from '../cutover.js'
import { dropCommand } from '../drop.js'

function spyExit() {
  return vi
    .spyOn(process, 'exit')
    .mockImplementation((() => undefined) as never)
}

/** Columns the faked catalog reports as EQL-domain typed. Empty = pure v2. */
let eqlColumns: { column: string; domain_name: string }[] = []
/** Columns the faked catalog reports as existing at all. */
let existingColumns: string[] = []

/**
 * Route on the catalog statements these paths issue. Each is matched on text
 * unique to it, and ORDER MATTERS: three of them end in `AS exists`, and
 * `columnExists` and `listEncryptedColumns` both embed the same shared
 * `to_regclass` expression. Matching loosely silently answers the wrong probe —
 * routing the v2 pending-config check into `columnExists` made cutover report
 * "no pending EQL configuration" instead of running the ladder.
 */
function fakeCatalog() {
  queryMock.mockImplementation(async (sql: string, params?: unknown[]) => {
    if (typeof sql !== 'string') return { rows: [] }
    // The v2 config machine exists…
    if (sql.includes("to_regclass('public.eql_v2_configuration')")) {
      return { rows: [{ exists: 'eql_v2_configuration' }] }
    }
    // …and holds a pending row to promote.
    if (sql.includes("state = 'pending'")) return { rows: [{ exists: true }] }
    if (sql.includes('typname AS domain_name')) return { rows: eqlColumns }
    if (sql.includes('pg_attribute') && sql.includes('AS exists')) {
      return {
        rows: [{ exists: existingColumns.includes(String(params?.[2])) }],
      }
    }
    return { rows: [] }
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  // The hint `encrypt backfill` records for EVERY column, v2 included. It is
  // what used to be discarded into a guess, and what must now be ignored
  // harmlessly on a table with no v3 columns to mis-claim.
  migrateMocks.readManifest.mockResolvedValue({
    tables: {
      users: [{ column: 'ssn', encryptedColumn: 'ssn_encrypted' }],
    },
  })
  migrateMocks.progress.mockResolvedValue({ phase: 'cut-over' })
  eqlColumns = []
  existingColumns = ['ssn', 'ssn_encrypted']
  fakeCatalog()
})

describe('the pure-v2 lifecycle, resolved for real end to end', () => {
  it('generates the v2 plaintext drop for a table whose encrypted column is legacy v2', async () => {
    const exitSpy = spyExit()

    await dropCommand({ table: 'users', column: 'ssn' })

    expect(exitSpy).not.toHaveBeenCalled()

    // Reached the v2 ladder: `<col>_plaintext`, not the v3 target `<col>`.
    const sql = writeFileMock.mock.calls[0]?.[1] as string
    expect(sql).toContain('DROP COLUMN "ssn_plaintext"')
    // The v3-only coverage gate must not run on a v2 column.
    expect(migrateMocks.countUnencrypted).not.toHaveBeenCalled()
  })

  it('runs the v2 rename and config promotion for a table with no EQL v3 columns', async () => {
    migrateMocks.progress.mockResolvedValue({ phase: 'backfilled' })

    const exitSpy = spyExit()

    await cutoverCommand({ table: 'users', column: 'ssn' })

    expect(exitSpy).not.toHaveBeenCalled()
    expect(migrateMocks.renameEncryptedColumns).toHaveBeenCalled()
    expect(migrateMocks.migrateConfig).toHaveBeenCalled()
    expect(migrateMocks.activateConfig).toHaveBeenCalled()
    expect(p.log.error).not.toHaveBeenCalled()
  })

  it('refuses both commands when the table also holds an unidentifiable EQL v3 column', async () => {
    // The mixed table from #772 finding 7. Same manifest hint, same v2 pair —
    // the ONLY difference is an unrelated v3 column, which is what makes the
    // recorded pairing meaningful and a fall-through a guess. Crossing this
    // boundary is what neither existing half of the coverage can see.
    eqlColumns = [{ column: 'email_enc', domain_name: 'eql_v3_text_search' }]
    const exitSpy = spyExit()

    await dropCommand({ table: 'users', column: 'ssn' })
    await cutoverCommand({ table: 'users', column: 'ssn' })

    // Refusing is the point: both must exit non-zero rather than act on
    // `email_enc`, the unrelated v3 column the sole-EQL-column rule would
    // otherwise claim.
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(migrateMocks.renameEncryptedColumns).not.toHaveBeenCalled()
    const errors = vi.mocked(p.log.error).mock.calls.flat().join('\n')
    expect(errors).toContain('is not an EQL v3 column')
    expect(errors).toContain('ssn_encrypted')
  })
})
