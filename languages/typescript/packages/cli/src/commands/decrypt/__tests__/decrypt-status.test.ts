/**
 * `stash decrypt status` must name the same plaintext twin `decrypt plan` and
 * `decrypt backfill` would, and flag a twin those commands would refuse. It
 * once derived the name itself and disagreed with them on an edge case.
 */

import type { MigrationStateRow } from '@cipherstash/migrate'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('pg', () => ({
  default: {
    Client: class {
      connect = vi.fn(async () => {})
      end = vi.fn(async () => {})
      query = vi.fn(async () => ({ rows: [] }))
    },
  },
}))

const readers = vi.hoisted(() => ({
  latestByColumnSafe: vi.fn(
    async (): Promise<Map<string, MigrationStateRow>> => new Map(),
  ),
  fetchPhysicalColumns: vi.fn(
    async (): Promise<Map<string, Map<string, string | null>>> => new Map(),
  ),
}))
vi.mock('@/commands/encrypt/lib/db-readers.js', () => readers)

vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  readManifest: vi.fn(async () => null),
}))
vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  log: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), success: vi.fn() },
}))
vi.mock('@/config/index.js', () => ({
  loadStashConfig: vi.fn(async () => ({ databaseUrl: 'postgres://test' })),
}))
vi.mock('@/commands/encrypt/context.js', () => ({
  loadEncryptionContext: vi.fn(),
  requireTable: vi.fn(),
}))
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: vi.fn(() => 'npm'),
  runnerCommand: vi.fn((_pm: string, ref: string) => `npx ${ref}`),
}))

import * as p from '@clack/prompts'
import { decryptStatusCommand } from '../status.js'

function event(
  overrides: Partial<MigrationStateRow> &
    Pick<MigrationStateRow, 'id' | 'columnName' | 'event' | 'phase'>,
): MigrationStateRow {
  return {
    tableName: 'users',
    cursorValue: null,
    rowsProcessed: null,
    rowsTotal: null,
    details: null,
    createdAt: new Date(0),
    ...overrides,
  }
}

/** The rendered status table, one string per data row. */
async function statusRows(): Promise<string[]> {
  await decryptStatusCommand()
  const table =
    vi
      .mocked(p.note)
      .mock.calls.find(
        ([, title]) => title === 'Reverse migration status',
      )?.[0] ?? ''
  return table.split('\n').slice(1)
}

describe('decrypt status', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    readers.latestByColumnSafe.mockResolvedValue(new Map())
  })

  it('derives the twin name with the same rule as plan, even for a column named _encrypted', async () => {
    readers.fetchPhysicalColumns.mockResolvedValue(
      new Map([
        [
          'users',
          new Map<string, string | null>([
            ['_encrypted', 'eql_v3_text'],
            ['email_encrypted', 'eql_v3_text_search'],
          ]),
        ],
      ]),
    )

    const rows = await statusRows()

    expect(rows.find((row) => row.includes('_encrypted '))).toContain(
      '_encrypted_plaintext (text, to add)',
    )
    expect(rows.find((row) => row.includes('email_encrypted'))).toContain(
      'email (text, to add)',
    )
  })

  it('flags a derived twin that is itself an EQL column, which plan and backfill refuse', async () => {
    readers.fetchPhysicalColumns.mockResolvedValue(
      new Map([
        [
          'users',
          new Map<string, string | null>([
            ['email_encrypted', 'eql_v3_text_search'],
            ['email', 'eql_v3_text_eq'],
          ]),
        ],
      ]),
    )

    const rows = await statusRows()

    const row = rows.find((r) => r.startsWith('users  email_encrypted')) ?? ''
    expect(row).toContain('plaintext-col-is-eql')
    expect(row).not.toContain('plaintext-col-missing')
  })

  it('shows a column whose earlier reverse lifecycle finished as starting over', async () => {
    readers.fetchPhysicalColumns.mockResolvedValue(
      new Map([
        [
          'users',
          new Map<string, string | null>([
            ['email_encrypted', 'eql_v3_text_search'],
            ['email', null],
          ]),
        ],
      ]),
    )
    readers.latestByColumnSafe.mockResolvedValue(
      new Map([
        [
          'users.email_encrypted',
          event({
            id: '10',
            columnName: 'email_encrypted',
            event: 'encrypted_dropped',
            phase: 'encrypted-dropped',
            details: { plaintextColumn: 'old_email' },
          }),
        ],
        [
          'users.old_email',
          event({
            id: '12',
            columnName: 'old_email',
            event: 'dual_writing',
            phase: 'dual-writing',
          }),
        ],
      ]),
    )

    const rows = await statusRows()

    const row = rows.find((r) => r.startsWith('users  email_encrypted')) ?? ''
    expect(row).not.toContain('encrypted-dropped')
    expect(row).not.toContain('old_email')
    expect(row).toMatch(/email_encrypted\s+eql_v3_text_search\s+email\s/)
  })
})
