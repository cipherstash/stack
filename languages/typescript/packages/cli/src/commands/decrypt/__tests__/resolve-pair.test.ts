/**
 * Pins how `stash decrypt` pairs an encrypted column with its plaintext twin.
 *
 * The pairing is what every later step trusts: the backfill fills that column,
 * and `decrypt drop`'s coverage gate verifies it before destroying the
 * ciphertext. A pairing that silently drifted — a flag naming a different
 * column mid-migration — would let that gate pass against the wrong column.
 *
 * The catalog probes are replaced; the `cs_migrations` history is served by a
 * fake client, so the twin rules run for real in `ColumnMigration`.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { EncryptedColumnInfo } from '@cipherstash/migrate'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const probes = vi.hoisted(() => ({
  listEncryptedColumns: vi.fn(async (): Promise<EncryptedColumnInfo[]> => []),
  columnExists: vi.fn(async () => true),
  detectColumnEqlVersion: vi.fn(async (): Promise<2 | 3 | null> => null),
  columnSqlType: vi.fn(async (): Promise<string | null> => null),
}))
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  ...probes,
}))
vi.mock('@/commands/encrypt/context.js', () => ({
  loadEncryptionContext: vi.fn(),
  requireTable: vi.fn(),
}))

import type pg from 'pg'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'
import {
  type DecryptPair,
  openForwardMigrationMessage,
  PlaintextColumnIsEqlError,
  resolveDecryptPair,
  twinHazardMessage,
} from '../lib/resolve-pair.js'
import { fakeMigration } from './fake-migration.js'

const EMAIL_ENC: EncryptedColumnInfo = {
  column: 'email_encrypted',
  domain: 'eql_v3_text_search',
  version: 3,
}

/** A raw `cs_migrations` row, as the driver returns it. */
interface RawEvent {
  id: number
  column: string
  event: string
  phase: string
  details?: Record<string, unknown>
}

let events: RawEvent[] = []
/** Answers `ColumnMigration`'s history read from {@link events}. */
const db = {
  query: vi.fn(async (_sql: string, params: unknown[]) => ({
    rows: events
      .filter((e) => e.column === params[1])
      .map((e) => ({
        id: String(e.id),
        table_name: 'users',
        column_name: e.column,
        event: e.event,
        phase: e.phase,
        cursor_value: null,
        rows_processed: null,
        rows_total: null,
        details: e.details ?? null,
        created_at: new Date(0),
      })),
  })),
} as unknown as pg.ClientBase

const recorded = (id: number, plaintextColumn: string): RawEvent => ({
  id,
  column: 'email_encrypted',
  event: 'decrypt_checkpoint',
  phase: 'decrypting',
  details: { plaintextColumn },
})

async function failure(promise: Promise<unknown>): Promise<Error> {
  const error = await promise.catch((e: unknown) => e)
  expect(error).toBeInstanceOf(BackfillConfigError)
  return error as Error
}

describe('resolveDecryptPair', () => {
  const cwd = process.cwd()
  let dir: string

  beforeEach(() => {
    vi.clearAllMocks()
    events = []
    dir = mkdtempSync(join(tmpdir(), 'resolve-pair-'))
    process.chdir(dir)
    probes.listEncryptedColumns.mockResolvedValue([EMAIL_ENC])
    probes.detectColumnEqlVersion.mockResolvedValue(null)
    probes.columnSqlType.mockResolvedValue(null)
  })

  afterEach(() => {
    process.chdir(cwd)
    rmSync(dir, { recursive: true, force: true })
  })

  it('reads the forward history recorded under the twin’s name', async () => {
    events = [
      { id: 3, column: 'email', event: 'backfilled', phase: 'backfilled' },
    ]

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.migration.blockedBy).toEqual({
      direction: 'forward',
      column: 'email',
      phase: 'backfilled',
    })
    expect(pair.migration.phase).toBeNull()
  })

  it('a drop generated in THIS column migration (not yet applied, or aborted) keeps it current', async () => {
    events = [
      {
        id: 10,
        column: 'email_encrypted',
        event: 'encrypted_dropped',
        phase: 'encrypted-dropped',
        details: { plaintextColumn: 'contact_email' },
      },
      // Older than the drop: the forward history that preceded the reversal.
      { id: 4, column: 'contact_email', event: 'dropped', phase: 'dropped' },
    ]

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.migration.phase).toBe('encrypted-dropped')
    expect(pair).toMatchObject({
      plaintextColumn: 'contact_email',
      via: 'recorded',
    })
  })

  it('a column migration that finished before the column was encrypted again neither binds nor counts', async () => {
    events = [
      {
        id: 10,
        column: 'email_encrypted',
        event: 'encrypted_dropped',
        phase: 'encrypted-dropped',
        details: { plaintextColumn: 'contact_email' },
      },
      // A forward rollout AFTER the drop re-created the encrypted column.
      {
        id: 12,
        column: 'contact_email',
        event: 'dual_writing',
        phase: 'dual-writing',
      },
    ]

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
      plaintextColumn: 'email',
    })
    expect(pair.migration.phase).toBeNull()
    expect(pair).toMatchObject({ plaintextColumn: 'email', via: 'flag' })
  })

  it('maps the domain back to its plaintext type', async () => {
    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.domain).toBe('eql_v3_text_search')
    expect(pair.mapping?.sqlType).toBe('text')
  })

  it('prefers the original name the forward manifest recorded', async () => {
    mkdirSync(join(dir, '.cipherstash'))
    writeFileSync(
      join(dir, '.cipherstash', 'migrations.json'),
      JSON.stringify({
        version: 1,
        tables: {
          users: [
            {
              column: 'email_address',
              castAs: 'text',
              indexes: [],
              targetPhase: 'dropped',
              encryptedColumn: 'email_encrypted',
            },
          ],
        },
      }),
    )

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair).toMatchObject({
      plaintextColumn: 'email_address',
      via: 'manifest',
    })
  })

  it('falls back to the _encrypted convention, then to <name>_plaintext', async () => {
    const conventional = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(conventional).toMatchObject({
      plaintextColumn: 'email',
      via: 'convention',
    })

    probes.listEncryptedColumns.mockResolvedValue([
      { column: 'secret', domain: 'eql_v3_text', version: 3 },
    ])
    const fallback = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'secret',
    })
    expect(fallback).toMatchObject({
      plaintextColumn: 'secret_plaintext',
      via: 'fallback',
    })
  })

  it('reuses the pairing an earlier reverse run recorded', async () => {
    events = [recorded(1, 'contact_email')]

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair).toMatchObject({
      plaintextColumn: 'contact_email',
      via: 'recorded',
    })
  })

  it('refuses a --plaintext-column that contradicts the recorded pairing', async () => {
    events = [recorded(1, 'contact_email')]

    const error = await failure(
      resolveDecryptPair(db, {
        table: 'users',
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'email',
      }),
    )
    expect(error.message).toContain(
      'already being migrated with "contact_email"',
    )
    expect(error.message).toContain('coverage check')
    expect(error.message).toContain('Drop --plaintext-column')
  })

  it('does not suggest the recorded column when nothing is recorded', async () => {
    const error = await failure(
      resolveDecryptPair(db, {
        table: 'users',
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'email_encrypted',
      }),
    )
    expect(error.message).toContain('cannot be email_encrypted itself')
    expect(error.message).not.toContain('recorded column')
    expect(error.message).toContain('Pass a different --plaintext-column')
  })

  it('ignores forward history under the same key — only reverse events pair', async () => {
    events = [
      {
        id: 1,
        column: 'email_encrypted',
        event: 'backfilled',
        phase: 'backfilled',
        details: { plaintextColumn: 'not-a-reverse-record' },
      },
    ]

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.migration.latest).toBeNull()
    expect(pair.via).toBe('convention')
  })

  it('names a missing source column, listing the EQL columns that do exist', async () => {
    probes.columnExists.mockResolvedValue(false)

    const error = await failure(
      resolveDecryptPair(db, { table: 'users', encryptedColumn: 'email' }),
    )
    expect(error.message).toContain('Column email does not exist on users')
    expect(error.message).toContain('email_encrypted')
  })

  it('refuses a source that is plaintext already', async () => {
    probes.columnExists.mockResolvedValue(true)

    const error = await failure(
      resolveDecryptPair(db, { table: 'users', encryptedColumn: 'email' }),
    )
    expect(error.message).toContain('is not an EQL v3 column')
  })

  it('refuses a target that is itself encrypted', async () => {
    probes.detectColumnEqlVersion.mockResolvedValue(3)

    const error = await failure(
      resolveDecryptPair(db, {
        table: 'users',
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'other_encrypted',
      }),
    )
    expect(error.message).toContain('is itself an EQL v3 column')
    expect(error).toBeInstanceOf(PlaintextColumnIsEqlError)
  })

  it('reports the twin’s declared type once it exists', async () => {
    probes.columnSqlType.mockResolvedValue('character varying(255)')

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.plaintextSqlType).toBe('character varying(255)')
  })
})

describe('openForwardMigrationMessage and twinHazardMessage', () => {
  function twin(overrides: Partial<DecryptPair> = {}): DecryptPair {
    return {
      table: 'users',
      encryptedColumn: 'email_encrypted',
      domain: 'eql_v3_text_search',
      mapping: null,
      plaintextColumn: 'email',
      via: 'manifest',
      plaintextSqlType: 'text',
      migration: fakeMigration(),
      ...overrides,
    }
  }

  it.each([
    'schema-added',
    'dual-writing',
    'backfilling',
    'backfilled',
  ] as const)(
    'refuses the source column of a forward migration still open at %s',
    (phase) => {
      const migration = fakeMigration({
        blockedBy: { direction: 'forward', column: 'email', phase },
      })
      expect(openForwardMigrationMessage(twin({ migration }))).toContain(
        `still open at '${phase}'`,
      )
    },
  )

  it('does not refuse when no forward column migration is open', () => {
    expect(openForwardMigrationMessage(twin())).toBeNull()
  })

  it('explains both ways forward, with names only', () => {
    const message = twinHazardMessage(twin())
    expect(message).toContain('users.email already holds values')
    expect(message).toContain(
      '--force  overwrite every row of email with the decrypted ciphertext',
    )
    expect(message).toContain(
      '--confirm-plaintext-current  keep the existing values',
    )
  })
})
