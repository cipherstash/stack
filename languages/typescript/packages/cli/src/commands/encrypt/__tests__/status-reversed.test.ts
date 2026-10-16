/**
 * `stash decrypt drop` no longer removes the column's entry from
 * `.cipherstash/migrations.json` when it generates the drop (the migration's
 * apply-time check can still abort). Until the user removes the entry, the
 * encrypted column's absence is intended, and `stash encrypt status` must say
 * so rather than report it as drift.
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
  fetchActiveEqlConfig: vi.fn(async () => new Map()),
  fetchPhysicalColumns: vi.fn(
    async (): Promise<Map<string, Map<string, string | null>>> =>
      new Map([['users', new Map<string, string | null>([['email', null]])]]),
  ),
}))
vi.mock('../lib/db-readers.js', () => readers)

vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  readManifest: vi.fn(async () => ({
    version: 1,
    tables: {
      users: [
        {
          column: 'email',
          castAs: 'text',
          indexes: [],
          targetPhase: 'dropped',
          encryptedColumn: 'email_encrypted',
        },
      ],
    },
  })),
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
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: vi.fn(() => 'npm'),
  runnerCommand: vi.fn((_pm: string, ref: string) => `npx ${ref}`),
}))

import * as p from '@clack/prompts'
import { statusCommand } from '../status.js'

async function emailRow(): Promise<string> {
  await statusCommand()
  const table =
    vi
      .mocked(p.note)
      .mock.calls.find(
        ([, title]) => title === 'Column migration status',
      )?.[0] ?? ''
  return table.split('\n').find((line) => line.startsWith('users')) ?? ''
}

describe('encrypt status for a reversed column', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('reports a missing encrypted column as drift when nothing reversed it', async () => {
    readers.latestByColumnSafe.mockResolvedValue(new Map())

    expect(await emailRow()).toContain('encrypted-col-missing')
  })

  it("reports it as reversed once `decrypt drop` recorded 'encrypted-dropped'", async () => {
    readers.latestByColumnSafe.mockResolvedValue(
      new Map([
        [
          'users.email_encrypted',
          {
            id: '9',
            tableName: 'users',
            columnName: 'email_encrypted',
            event: 'encrypted_dropped',
            phase: 'encrypted-dropped',
            cursorValue: null,
            rowsProcessed: null,
            rowsTotal: null,
            details: { plaintextColumn: 'email' },
            createdAt: new Date(0),
          },
        ],
      ]),
    )

    const row = await emailRow()
    expect(row).toContain('reversed (remove from migrations.json)')
    expect(row).not.toContain('encrypted-col-missing')
  })
})
