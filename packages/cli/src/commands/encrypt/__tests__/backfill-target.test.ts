/**
 * Pins `assertEqlV3Target`'s two distinct failure modes.
 *
 * `detectColumnEqlVersion` returns `null` for BOTH "the column exists but its
 * type is not an `eql_v3_*` domain" AND "there is no such column". Collapsing
 * them into one message told a user who simply had not added the encrypted
 * column yet that they were on a legacy EQL v2 column — a diagnosis with no
 * relation to their actual problem, and a remedy (migrate the domain) they
 * cannot act on.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

// Only the two catalog probes are replaced; everything else in
// `@cipherstash/migrate` stays real so a rename on either side fails loudly
// rather than silently mocking a function that no longer exists.
const detectColumnEqlVersion = vi.hoisted(() =>
  vi.fn(async (): Promise<2 | 3 | null> => null),
)
const columnExists = vi.hoisted(() => vi.fn(async (): Promise<boolean> => true))
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  detectColumnEqlVersion,
  columnExists,
}))

// `backfill.ts` pulls in the encryption-client loader and clack at module
// scope; neither is reachable from the guard, but both must import cleanly.
vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: {
    info: vi.fn(),
    success: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    step: vi.fn(),
  },
}))
vi.mock('@/config/index.js', () => ({
  loadStashConfig: vi.fn(async () => ({ databaseUrl: 'postgres://test' })),
}))
vi.mock('../context.js', () => ({
  loadEncryptionContext: vi.fn(async () => ({ client: {}, tables: new Map() })),
  requireTable: vi.fn(),
}))

import type pg from 'pg'
import { assertEqlV3Target, BackfillConfigError } from '../backfill.js'

// The guard only ever hands this to the mocked probes.
const db = {} as pg.ClientBase

describe('assertEqlV3Target', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('accepts an EQL v3 domain without probing for existence', async () => {
    detectColumnEqlVersion.mockResolvedValue(3)

    await expect(
      assertEqlV3Target(db, 'users', 'email_encrypted'),
    ).resolves.toBe(3)
    // The happy path must not pay for a second catalog round-trip.
    expect(columnExists).not.toHaveBeenCalled()
  })

  it('reports a MISSING column as missing, not as legacy EQL v2', async () => {
    detectColumnEqlVersion.mockResolvedValue(null)
    columnExists.mockResolvedValue(false)

    const error = await assertEqlV3Target(db, 'users', 'email_encrypted').catch(
      (e: unknown) => e,
    )

    expect(error).toBeInstanceOf(BackfillConfigError)
    const message = (error as Error).message
    expect(message).toContain('does not exist on users')
    expect(message).toContain('eql_v3_*')
    // The remedy is to add the column, not to migrate a domain that isn't there.
    expect(message).toContain('--encrypted-column')
    expect(message).not.toContain('EQL v2')
  })

  it('keeps the legacy-v2 diagnosis for a column that DOES exist', async () => {
    detectColumnEqlVersion.mockResolvedValue(null)
    columnExists.mockResolvedValue(true)

    const error = await assertEqlV3Target(db, 'users', 'email_encrypted').catch(
      (e: unknown) => e,
    )

    expect(error).toBeInstanceOf(BackfillConfigError)
    const message = (error as Error).message
    expect(message).toContain('is not an EQL v3 domain')
    expect(message).toContain('no longer backfills legacy EQL v2 columns')
    expect(message).not.toContain('does not exist')
  })
})
