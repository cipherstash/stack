/**
 * A stand-in for `@cipherstash/migrate`'s `ColumnMigration`, for the command
 * tests that mock the database away. Its state comes from the real rules
 * (`deriveColumnMigration`, `planPassFor`) over the history given, so a test
 * describes the event history, not the answers; only the methods that write
 * are spies. The rules themselves are covered in `@cipherstash/migrate`, and
 * the commands against real Postgres in `decrypt-lifecycle.live.test.ts`.
 */

import {
  type ColumnMigration,
  ColumnMigrationError,
  deriveColumnMigration,
  type MigrationEvent,
  type MigrationPhase,
  type MigrationStateRow,
  type OpenCounterpart,
  planPassFor,
} from '@cipherstash/migrate'
import { type Mock, vi } from 'vitest'

let nextId = 1

/** One reverse event under `users.email_encrypted`, naming the twin. */
export function reverseEvent(
  event: MigrationEvent,
  phase: MigrationPhase,
  extra: Partial<MigrationStateRow> = {},
): MigrationStateRow {
  return {
    id: String(nextId++),
    tableName: 'users',
    columnName: 'email_encrypted',
    event,
    phase,
    cursorValue: null,
    rowsProcessed: null,
    rowsTotal: null,
    details: { plaintextColumn: 'email' },
    createdAt: new Date(0),
    ...extra,
  }
}

/** A reverse column migration mid-pass. */
export const inFlight = (): MigrationStateRow[] => [
  reverseEvent('decrypt_dual_writing', 'decrypt-dual-writing'),
  reverseEvent('decrypt_checkpoint', 'decrypting', {
    cursorValue: '5',
    rowsProcessed: 5,
    rowsTotal: 10,
  }),
]

/** A reverse column migration whose backfill completed. */
export const decrypted = (): MigrationStateRow[] => [
  reverseEvent('decrypt_dual_writing', 'decrypt-dual-writing'),
  reverseEvent('decrypted', 'decrypted', { rowsProcessed: 10, rowsTotal: 10 }),
]

/**
 * The spies are typed from `ColumnMigration` itself, so a change to a real
 * method's signature fails these tests' typecheck instead of passing them.
 */
export type FakeMigration = ColumnMigration & {
  existingTwinValues: Mock<ColumnMigration['existingTwinValues']>
  planPass: Mock<ColumnMigration['planPass']>
  counterpartMessage: Mock<ColumnMigration['counterpartMessage']>
  confirmDualWrites: Mock<ColumnMigration['confirmDualWrites']>
  recordDropGenerated: Mock<ColumnMigration['recordDropGenerated']>
  recordSourceRemoved: Mock<ColumnMigration['recordSourceRemoved']>
}

export function fakeMigration(
  opts: {
    history?: MigrationStateRow[]
    /** Events under the recorded twin, which can make `history` finished. */
    recordedTwinHistory?: MigrationStateRow[]
    twin?: string
    blockedBy?: OpenCounterpart | null
    twinHasValues?: boolean
  } = {},
): FakeMigration {
  const state = deriveColumnMigration({
    direction: 'reverse',
    history: opts.history ?? [],
    recordedTwinHistory: opts.recordedTwinHistory,
  })
  const twinHasValues = opts.twinHasValues ?? false
  const spies = {
    existingTwinValues: vi.fn<ColumnMigration['existingTwinValues']>(
      async () => state.phase === null && twinHasValues,
    ),
    planPass: vi.fn<ColumnMigration['planPass']>(async ({ force }) =>
      planPassFor(state, {
        force,
        twinHasValues: state.phase === null && twinHasValues,
      }),
    ),
    counterpartMessage: vi.fn<ColumnMigration['counterpartMessage']>(
      () => null,
    ),
    confirmDualWrites: vi.fn<ColumnMigration['confirmDualWrites']>(),
    recordDropGenerated: vi.fn<ColumnMigration['recordDropGenerated']>(),
    recordSourceRemoved: vi.fn<ColumnMigration['recordSourceRemoved']>(),
  }
  // `ColumnMigration` has private members, so no object literal is one; the
  // spies above are what carry its method types.
  const fake = {
    ...state,
    table: 'users',
    column: 'email_encrypted',
    twin: { column: opts.twin ?? 'email', via: 'convention' as const },
    blockedBy: opts.blockedBy ?? null,
    ...spies,
  } as unknown as FakeMigration
  // The real rules: in progress, record nothing unless a waiver closes a
  // waivable obligation, and refuse one that is not.
  fake.confirmDualWrites.mockImplementation(async ({ waiver } = {}) => {
    let existingTwinValues: boolean
    if (state.phase !== null) {
      const owed = state.obligations[0]
      if (waiver === undefined || owed === undefined) return fake
      if (!owed.waivable) {
        throw new ColumnMigrationError(
          'waiver-refused',
          'A forced pass over users.email has already started.',
        )
      }
      existingTwinValues = true
    } else {
      existingTwinValues = twinHasValues
    }
    return fakeMigration({
      ...opts,
      history: [
        ...(opts.history ?? []),
        reverseEvent('decrypt_dual_writing', 'decrypt-dual-writing', {
          details: {
            plaintextColumn: 'email',
            ...(existingTwinValues ? { existingTwinValues: true } : {}),
            ...(existingTwinValues && waiver !== undefined ? { waiver } : {}),
          },
        }),
      ],
    })
  })
  fake.recordDropGenerated.mockImplementation(async () => fake)
  fake.recordSourceRemoved.mockImplementation(async () => fake)
  return fake
}
