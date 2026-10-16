/**
 * Pins how `stash decrypt` pairs an encrypted column with its plaintext twin.
 *
 * The pairing is what every later step trusts: the backfill fills that column,
 * and `decrypt drop`'s coverage gate verifies it before destroying the
 * ciphertext. A pairing that silently drifted — a flag naming a different
 * column mid-lifecycle — would let that gate pass against the wrong column.
 */

import type {
  EncryptedColumnInfo,
  MigrationStateRow,
} from '@cipherstash/migrate'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Only the catalog/state probes are replaced; the domain mapping and phase
// predicates stay real so a rename on either side fails loudly.
const probes = vi.hoisted(() => ({
  listEncryptedColumns: vi.fn(async (): Promise<EncryptedColumnInfo[]> => []),
  columnExists: vi.fn(async () => true),
  detectColumnEqlVersion: vi.fn(async (): Promise<2 | 3 | null> => null),
  columnSqlType: vi.fn(async (): Promise<string | null> => null),
  columnHasValues: vi.fn(async () => false),
  progress: vi.fn(
    async (
      _client: unknown,
      _table: string,
      _column: string,
    ): Promise<Partial<MigrationStateRow> | null> => null,
  ),
  readManifest: vi.fn(async (): Promise<unknown> => null),
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
  assessExistingTwin,
  type DecryptPair,
  derivePlaintextName,
  openForwardMigrationMessage,
  resolveDecryptPair,
  twinHazardMessage,
} from '../lib/resolve-pair.js'

const db = {} as pg.ClientBase
const EMAIL_ENC: EncryptedColumnInfo = {
  column: 'email_encrypted',
  domain: 'eql_v3_text_search',
  version: 3,
}

function reverseState(plaintextColumn: string): Partial<MigrationStateRow> {
  return {
    event: 'decrypt_checkpoint',
    phase: 'decrypting',
    details: { plaintextColumn },
  }
}

async function failure(promise: Promise<unknown>): Promise<Error> {
  const error = await promise.catch((e: unknown) => e)
  expect(error).toBeInstanceOf(BackfillConfigError)
  return error as Error
}

describe('resolveDecryptPair', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    probes.listEncryptedColumns.mockResolvedValue([EMAIL_ENC])
    probes.detectColumnEqlVersion.mockResolvedValue(null)
    probes.columnSqlType.mockResolvedValue(null)
    probes.columnHasValues.mockResolvedValue(false)
    probes.progress.mockResolvedValue(null)
    probes.readManifest.mockResolvedValue(null)
  })

  /** `progress` answers per column: reverse history under the encrypted
   * column, forward history under the plaintext name. */
  function history(byColumn: Record<string, Partial<MigrationStateRow>>) {
    probes.progress.mockImplementation(
      async (_client, _table, column) => byColumn[column] ?? null,
    )
  }

  it('reads the forward history recorded under the twin’s name', async () => {
    history({ email: { id: '3', event: 'backfilled', phase: 'backfilled' } })

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.forwardState?.phase).toBe('backfilled')
    expect(pair.lifecycleActive).toBe(false)
  })

  it('a drop generated in THIS lifecycle (not yet applied, or aborted) keeps it active', async () => {
    history({
      email_encrypted: {
        id: '10',
        event: 'encrypted_dropped',
        phase: 'encrypted-dropped',
        details: { plaintextColumn: 'contact_email' },
      },
      // Older than the drop: the forward history that preceded the reversal.
      contact_email: { id: '4', event: 'backfilled', phase: 'backfilled' },
    })

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.lifecycleActive).toBe(true)
    expect(pair).toMatchObject({
      plaintextColumn: 'contact_email',
      via: 'recorded',
    })
  })

  it('a lifecycle that finished before the column was encrypted again neither binds nor counts as active', async () => {
    history({
      email_encrypted: {
        id: '10',
        event: 'encrypted_dropped',
        phase: 'encrypted-dropped',
        details: { plaintextColumn: 'contact_email' },
      },
      // A forward rollout AFTER the drop re-created the encrypted column.
      contact_email: { id: '12', event: 'dual_writing', phase: 'dual-writing' },
    })

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
      plaintextColumn: 'email',
    })
    expect(pair.lifecycleActive).toBe(false)
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
    probes.readManifest.mockResolvedValue({
      version: 1,
      tables: {
        users: [
          { column: 'email_address', encryptedColumn: 'email_encrypted' },
        ],
      },
    })

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
    probes.progress.mockResolvedValue(reverseState('contact_email'))

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
    probes.progress.mockResolvedValue(reverseState('contact_email'))

    const error = await failure(
      resolveDecryptPair(db, {
        table: 'users',
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'email',
      }),
    )
    expect(error.message).toContain(
      'already being reversed into "contact_email"',
    )
    expect(error.message).toContain('coverage check')
  })

  it('ignores forward history under the same key — only reverse events pair', async () => {
    probes.progress.mockResolvedValue({
      event: 'backfilled',
      phase: 'backfilled',
      details: { plaintextColumn: 'not-a-reverse-record' },
    })

    const pair = await resolveDecryptPair(db, {
      table: 'users',
      encryptedColumn: 'email_encrypted',
    })
    expect(pair.state).toBeNull()
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

describe('derivePlaintextName', () => {
  it('strips the _encrypted convention', () => {
    expect(derivePlaintextName('email_encrypted')).toEqual({
      name: 'email',
      via: 'convention',
    })
  })

  it('never derives an empty name from a column called exactly _encrypted', () => {
    expect(derivePlaintextName('_encrypted')).toEqual({
      name: '_encrypted_plaintext',
      via: 'fallback',
    })
    expect(derivePlaintextName('secret')).toEqual({
      name: 'secret_plaintext',
      via: 'fallback',
    })
  })
})

describe('assessExistingTwin', () => {
  const db = {} as pg.ClientBase

  function twin(overrides: Partial<DecryptPair> = {}): DecryptPair {
    return {
      table: 'users',
      encryptedColumn: 'email_encrypted',
      domain: 'eql_v3_text_search',
      mapping: null,
      plaintextColumn: 'email',
      via: 'manifest',
      plaintextSqlType: 'text',
      state: null,
      lifecycleActive: false,
      forwardState: null,
      ...overrides,
    }
  }

  function forwardAt(phase: MigrationStateRow['phase']): MigrationStateRow {
    return {
      id: '3',
      tableName: 'users',
      columnName: 'email',
      event: 'backfilled',
      phase,
      cursorValue: null,
      rowsProcessed: null,
      rowsTotal: null,
      details: null,
      createdAt: new Date(0),
    }
  }

  beforeEach(() => {
    vi.clearAllMocks()
    probes.columnHasValues.mockResolvedValue(false)
  })

  it('trusts a twin the reverse lifecycle in progress filled, without scanning it', async () => {
    probes.columnHasValues.mockResolvedValue(true)

    expect(await assessExistingTwin(db, twin({ lifecycleActive: true }))).toBe(
      null,
    )
    expect(probes.columnHasValues).not.toHaveBeenCalled()
  })

  it('has nothing to check before the twin exists', async () => {
    expect(
      await assessExistingTwin(db, twin({ plaintextSqlType: null })),
    ).toBeNull()
  })

  it('accepts an empty twin with no forward history', async () => {
    expect(await assessExistingTwin(db, twin())).toBeNull()
  })

  it('flags a twin that already holds values', async () => {
    probes.columnHasValues.mockResolvedValue(true)

    expect(await assessExistingTwin(db, twin())).toEqual({
      kind: 'prepopulated',
    })
  })

  it.each([
    'schema-added',
    'dual-writing',
    'backfilling',
    'backfilled',
  ] as const)(
    'refuses the source column of a forward migration still open at %s',
    (phase) => {
      expect(
        openForwardMigrationMessage(twin({ forwardState: forwardAt(phase) })),
      ).toContain(`still open at '${phase}'`)
    },
  )

  it("does not refuse once the forward migration reached 'dropped'", () => {
    expect(
      openForwardMigrationMessage(twin({ forwardState: forwardAt('dropped') })),
    ).toBeNull()
    expect(openForwardMigrationMessage(twin())).toBeNull()
  })

  it("a forward lifecycle at 'dropped' is no longer the source, but its values still count", async () => {
    expect(
      await assessExistingTwin(
        db,
        twin({ forwardState: forwardAt('dropped') }),
      ),
    ).toBeNull()

    // `dropped` is recorded when the drop is generated; if it was never
    // applied the old column is still there, full.
    probes.columnHasValues.mockResolvedValue(true)
    expect(
      await assessExistingTwin(
        db,
        twin({ forwardState: forwardAt('dropped') }),
      ),
    ).toEqual({ kind: 'prepopulated' })
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
