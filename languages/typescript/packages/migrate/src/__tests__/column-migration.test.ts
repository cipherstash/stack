/**
 * Table tests for the column-migration rules: event history in, the column
 * migration's `{ phase, obligations }` out. No database — the histories are
 * the `cs_migrations` rows `ColumnMigration.load` would read.
 */

import type { ClientBase } from 'pg'
import { describe, expect, expectTypeOf, it, vi } from 'vitest'
import {
  ColumnMigration,
  type ColumnMigrationState,
  deriveColumnMigration,
  deriveTwinName,
  manifestTwin,
  type Obligation,
  openCounterpart,
  type PassPlan,
  passProgress,
  planPassFor,
} from '../column-migration.js'
import type { Manifest } from '../manifest.js'
import type {
  MigrationEvent,
  MigrationPhase,
  MigrationStateRow,
} from '../state.js'

let nextId = 1
function ev(
  event: MigrationEvent,
  phase: MigrationPhase,
  details: Record<string, unknown> | null = null,
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
    details,
    createdAt: new Date(0),
    ...extra,
  }
}

const twin = { plaintextColumn: 'email' }
const forced = { ...twin, force: true }
const unforced = { ...twin, force: false }

// Reverse events, named for the table below.
const confirm = () =>
  ev('decrypt_dual_writing', 'decrypt-dual-writing', { ...twin })
const confirmOverValues = () =>
  ev('decrypt_dual_writing', 'decrypt-dual-writing', {
    ...twin,
    existingTwinValues: true,
  })
const confirmWaived = () =>
  ev('decrypt_dual_writing', 'decrypt-dual-writing', {
    ...twin,
    existingTwinValues: true,
    waiver: 'plaintext-current',
  })
const started = (details: Record<string, unknown>) =>
  ev('decrypt_started', 'decrypting', details)
const checkpoint = (details: Record<string, unknown>, cursor = '100') =>
  ev('decrypt_checkpoint', 'decrypting', details, { cursorValue: cursor })
const failed = (details: Record<string, unknown>, cursor: string | null) =>
  ev('error', 'decrypting', details, { cursorValue: cursor })
const completed = (details: Record<string, unknown>) =>
  ev('decrypted', 'decrypted', details)
const dropGenerated = () =>
  ev('encrypted_dropped', 'encrypted-dropped', { ...twin })

type Expected = Pick<ColumnMigrationState, 'phase' | 'open'> & {
  obligation: null | { reason: string; waivable: boolean }
}

const REVERSE_CASES: Array<{
  name: string
  history: () => MigrationStateRow[]
  expected: Expected
}> = [
  {
    name: 'no history: no column migration',
    history: () => [],
    expected: { phase: null, open: false, obligation: null },
  },
  {
    name: 'dual-writes confirmed over an empty twin: nothing owed',
    history: () => [confirm()],
    expected: { phase: 'decrypt-dual-writing', open: true, obligation: null },
  },
  {
    name: 'opened up front: confirmed over a twin that already held values',
    history: () => [confirmOverValues()],
    expected: {
      phase: 'decrypt-dual-writing',
      open: true,
      obligation: { reason: 'existing-values', waivable: true },
    },
  },
  {
    name: 'closed by a waiver recorded at confirmation',
    history: () => [confirmWaived()],
    expected: { phase: 'decrypt-dual-writing', open: true, obligation: null },
  },
  {
    name: 'closed by a waiver recorded on a later confirmation, before any pass',
    history: () => [confirmOverValues(), confirmWaived()],
    expected: { phase: 'decrypt-dual-writing', open: true, obligation: null },
  },
  {
    name: 'opened by a forced pass that started',
    history: () => [confirm(), started(forced)],
    expected: {
      phase: 'decrypting',
      open: true,
      obligation: { reason: 'forced-pass', waivable: false },
    },
  },
  {
    name: 'opened by a forced pass that failed before its first commit',
    history: () => [confirm(), started(forced), failed(forced, null)],
    expected: {
      phase: 'decrypting',
      open: true,
      obligation: { reason: 'forced-pass', waivable: false },
    },
  },
  {
    name: 'a forced pass started over an up-front obligation is no longer waivable',
    history: () => [confirmOverValues(), started(forced)],
    expected: {
      phase: 'decrypting',
      open: true,
      obligation: { reason: 'forced-pass', waivable: false },
    },
  },
  {
    name: 'closed by a completed forced pass',
    history: () => [
      confirmOverValues(),
      started(forced),
      checkpoint(forced),
      completed(forced),
    ],
    expected: { phase: 'decrypted', open: true, obligation: null },
  },
  {
    name: 'an unforced completion does not close it',
    history: () => [confirm(), started(forced), completed(unforced)],
    expected: {
      phase: 'decrypted',
      open: true,
      obligation: { reason: 'forced-pass', waivable: false },
    },
  },
  {
    name: 'unforced passes neither open nor close anything',
    history: () => [confirm(), started(unforced), completed(unforced)],
    expected: { phase: 'decrypted', open: true, obligation: null },
  },
  {
    name: 'a pass run with no dual-write confirmation is still scoped',
    history: () => [started(forced), checkpoint(forced)],
    expected: {
      phase: 'decrypting',
      open: true,
      obligation: { reason: 'forced-pass', waivable: false },
    },
  },
  {
    name: 'an obligation left open by an earlier column migration does not carry over',
    history: () => [confirmOverValues(), started(forced), confirm()],
    expected: { phase: 'decrypt-dual-writing', open: true, obligation: null },
  },
  {
    name: 'a generated drop is the current column migration, but no longer open',
    history: () => [
      confirm(),
      started(unforced),
      completed(unforced),
      dropGenerated(),
    ],
    expected: { phase: 'encrypted-dropped', open: false, obligation: null },
  },
  {
    name: 'forward events under the same key are not reverse history',
    history: () => [
      ev('backfill_checkpoint', 'backfilling', null, { cursorValue: '40' }),
    ],
    expected: { phase: null, open: false, obligation: null },
  },
]

describe('deriveColumnMigration (reverse)', () => {
  it.each(REVERSE_CASES)('$name', ({ history, expected }) => {
    const state = deriveColumnMigration({
      direction: 'reverse',
      history: history(),
    })
    expect(state.phase).toBe(expected.phase)
    expect(state.open).toBe(expected.open)
    const [obligation] = state.obligations
    expect(
      obligation === undefined
        ? null
        : { reason: obligation.reason, waivable: obligation.waivable },
    ).toEqual(expected.obligation)
    expect(state.obligations.length).toBeLessThanOrEqual(1)
  })

  it('records the twin the latest reverse event names', () => {
    const state = deriveColumnMigration({
      direction: 'reverse',
      history: [confirm(), started(unforced)],
    })
    expect(state.recordedTwin).toBe('email')
  })

  it('a generated drop superseded by a later forward column migration of the twin is history', () => {
    const history = [confirm(), completed(unforced), dropGenerated()]
    const forwardOfTwin = [
      ev('dual_writing', 'dual-writing', null, { columnName: 'email' }),
    ]
    const state = deriveColumnMigration({
      direction: 'reverse',
      history,
      recordedTwinHistory: forwardOfTwin,
    })
    expect(state.phase).toBeNull()
    expect(state.open).toBe(false)
    expect(state.recordedTwin).toBeUndefined()
    // …while forward events from BEFORE the drop leave it current.
    const before = [
      ev('dropped', 'dropped', null, { columnName: 'email', id: '0' }),
    ]
    expect(
      deriveColumnMigration({
        direction: 'reverse',
        history,
        recordedTwinHistory: before,
      }).phase,
    ).toBe('encrypted-dropped')
  })

  it('a forward drop superseded by a later reverse column migration of its twin is history', () => {
    // email encrypted into email_encrypted and dropped, then decrypted back
    // into email and email_encrypted dropped: encrypting email again starts
    // a new column migration, not the dropped one.
    const forwardTwin = { encryptedColumn: 'email_encrypted' }
    const history = [
      ev('dual_writing', 'dual-writing', forwardTwin, { columnName: 'email' }),
      ev('backfilled', 'backfilled', forwardTwin, { columnName: 'email' }),
      ev('dropped', 'dropped', forwardTwin, { columnName: 'email' }),
    ]
    const reverseOfTwin = [confirm(), completed(unforced), dropGenerated()]
    const state = deriveColumnMigration({
      direction: 'forward',
      history,
      recordedTwinHistory: reverseOfTwin,
    })
    expect(state.phase).toBeNull()
    expect(state.open).toBe(false)
    expect(state.recordedTwin).toBeUndefined()
    expect(deriveColumnMigration({ direction: 'forward', history }).phase).toBe(
      'dropped',
    )
  })

  it('reverse events of the twin from BEFORE a forward drop leave the drop current', () => {
    // An earlier round trip: email_encrypted decrypted back and dropped, then
    // email encrypted into email_encrypted again and dropped.
    const earlierReverse = [confirm(), completed(unforced), dropGenerated()]
    const forwardTwin = { encryptedColumn: 'email_encrypted' }
    const history = [
      ev('dual_writing', 'dual-writing', forwardTwin, { columnName: 'email' }),
      ev('backfilled', 'backfilled', forwardTwin, { columnName: 'email' }),
      ev('dropped', 'dropped', forwardTwin, { columnName: 'email' }),
    ]
    const state = deriveColumnMigration({
      direction: 'forward',
      history,
      recordedTwinHistory: earlierReverse,
    })
    expect(state.phase).toBe('dropped')
    expect(state.recordedTwin).toBe('email_encrypted')
  })
})

describe('deriveColumnMigration (reverse, events from an earlier release)', () => {
  it('a twin acknowledged with --force at confirm owes a forced pass', () => {
    const state = deriveColumnMigration({
      direction: 'reverse',
      history: [
        ev('decrypt_dual_writing', 'decrypt-dual-writing', {
          ...twin,
          existingPlaintext: 'prepopulated',
          acknowledgedWith: 'force',
        }),
      ],
    })
    expect(state.obligations).toMatchObject([
      { reason: 'existing-values', waivable: true },
    ])
  })

  it('a twin acknowledged as current at confirm owes nothing', () => {
    const state = deriveColumnMigration({
      direction: 'reverse',
      history: [
        ev('decrypt_dual_writing', 'decrypt-dual-writing', {
          ...twin,
          existingPlaintext: 'prepopulated',
          acknowledgedWith: 'confirm-plaintext-current',
        }),
      ],
    })
    expect(state.obligations).toEqual([])
  })
})

describe('deriveColumnMigration (forward)', () => {
  const fwd = (
    event: MigrationEvent,
    phase: MigrationPhase,
    details: Record<string, unknown> | null = null,
  ) => ev(event, phase, details, { columnName: 'email' })

  it('a forced pass interrupted by an older release (force only on started) stays owed', () => {
    const state = deriveColumnMigration({
      direction: 'forward',
      history: [
        fwd('dual_writing', 'dual-writing'),
        fwd('backfill_started', 'backfilling', { force: true }),
        fwd('backfill_checkpoint', 'backfilling', { chunkIndex: 0 }),
      ],
    })
    expect(state.obligations.map((o) => o.reason)).toEqual(['forced-pass'])
  })

  it('a forced pass an older release completed (force only on started) is not owed again', () => {
    const state = deriveColumnMigration({
      direction: 'forward',
      history: [
        fwd('dual_writing', 'dual-writing'),
        fwd('backfill_started', 'backfilling', { force: true }),
        fwd('backfill_checkpoint', 'backfilling', { chunkIndex: 0 }),
        fwd('backfilled', 'backfilled', {}),
      ],
    })
    expect(state.obligations).toEqual([])
  })

  it('an older unforced pass completing does not close a forced pass started after it', () => {
    const state = deriveColumnMigration({
      direction: 'forward',
      history: [
        fwd('dual_writing', 'dual-writing'),
        fwd('backfill_started', 'backfilling', { force: true }),
        fwd('backfill_started', 'backfilling', {}),
        fwd('backfilled', 'backfilled', {}),
      ],
    })
    expect(state.obligations.map((o) => o.reason)).toEqual(['forced-pass'])
  })

  it('a dropped forward column migration is finished', () => {
    const state = deriveColumnMigration({
      direction: 'forward',
      history: [fwd('dual_writing', 'dual-writing'), fwd('dropped', 'dropped')],
    })
    expect(state.phase).toBe('dropped')
    expect(state.open).toBe(false)
  })

  it('ignores reverse events', () => {
    const state = deriveColumnMigration({
      direction: 'forward',
      history: [confirm()],
    })
    expect(state.phase).toBeNull()
  })

  it('a completion whose details are a JSON scalar takes the mode of its pass', () => {
    // `details` is jsonb, so a hand-written row can hold a string.
    const scalar = 'x' as unknown as Record<string, unknown>
    const state = deriveColumnMigration({
      direction: 'forward',
      history: [
        fwd('dual_writing', 'dual-writing'),
        fwd('backfill_started', 'backfilling', { force: true }),
        fwd('backfilled', 'backfilled', scalar),
      ],
    })
    expect(state.phase).toBe('backfilled')
    expect(state.obligations).toEqual([])
  })
})

describe('ColumnMigration.load without cs_migrations', () => {
  const failingDb = (error: unknown) =>
    ({ query: vi.fn().mockRejectedValue(error) }) as unknown as ClientBase

  it.each([
    ['42P01', 'undefined_table'],
    ['3F000', 'invalid_schema_name'],
  ])('reads %s (%s) as no history', async (code) => {
    const migration = await ColumnMigration.load(
      failingDb(Object.assign(new Error('not installed'), { code })),
      {
        table: 'users',
        column: 'email_encrypted',
        direction: 'reverse',
        twin: 'email',
      },
    )
    expect(migration.phase).toBeNull()
    expect(migration.obligations).toEqual([])
  })

  it('rethrows any other error', async () => {
    const lost = new Error('connection lost')
    await expect(
      ColumnMigration.load(failingDb(lost), {
        table: 'users',
        column: 'email_encrypted',
        direction: 'reverse',
        twin: 'email',
      }),
    ).rejects.toBe(lost)
  })
})

describe('openCounterpart', () => {
  it('refuses a forward-source twin: a forward column migration not yet dropped', () => {
    const blocking = openCounterpart({
      direction: 'reverse',
      twin: 'email',
      twinHistory: [
        ev('dual_writing', 'dual-writing', null, { columnName: 'email' }),
        ev('backfilled', 'backfilled', null, { columnName: 'email' }),
      ],
    })
    expect(blocking).toEqual({
      direction: 'forward',
      column: 'email',
      phase: 'backfilled',
    })
  })

  it('a dropped forward column migration does not block the reverse one', () => {
    expect(
      openCounterpart({
        direction: 'reverse',
        twin: 'email',
        twinHistory: [ev('dropped', 'dropped', null, { columnName: 'email' })],
      }),
    ).toBeNull()
  })

  it('an open reverse column migration blocks a forward one on the same pair', () => {
    expect(
      openCounterpart({
        direction: 'forward',
        twin: 'email_encrypted',
        twinHistory: [started(unforced)],
      }),
    ).toEqual({
      direction: 'reverse',
      column: 'email_encrypted',
      phase: 'decrypting',
    })
  })

  it('a generated reverse drop does not block a forward one', () => {
    expect(
      openCounterpart({
        direction: 'forward',
        twin: 'email_encrypted',
        twinHistory: [completed(unforced), dropGenerated()],
      }),
    ).toBeNull()
  })
})

describe('planPassFor', () => {
  const state = (history: MigrationStateRow[]) =>
    deriveColumnMigration({ direction: 'reverse', history })

  it('an open obligation forces a run the caller did not force, and says why', () => {
    const plan = planPassFor(state([confirm(), started(forced)]), {
      force: false,
    })
    expect(plan).toMatchObject({ force: true, forcedBy: 'forced-pass' })
  })

  it('an up-front obligation forces the first run', () => {
    expect(
      planPassFor(state([confirmOverValues()]), { force: false }),
    ).toMatchObject({ force: true, forcedBy: 'existing-values' })
  })

  it('a caller-forced run says so', () => {
    expect(planPassFor(state([confirm()]), { force: true })).toMatchObject({
      force: true,
      forcedBy: 'caller',
    })
  })

  it('nothing owed and nothing asked: unforced', () => {
    expect(planPassFor(state([confirm()]), { force: false })).toMatchObject({
      force: false,
      forcedBy: null,
      resumeFrom: null,
    })
  })

  /** The history, and its last event (ids are assigned in call order). */
  const ending = (...rows: MigrationStateRow[]) =>
    [rows, rows[rows.length - 1]] as const

  it('resumes a checkpoint of the same mode', () => {
    const [history, last] = ending(
      confirm(),
      started(unforced),
      checkpoint(unforced, '200'),
    )
    expect(planPassFor(state(history), { force: false }).resumeFrom).toBe(last)
  })

  it('resumes an interrupted forced pass even when the caller did not force', () => {
    const [history, last] = ending(
      confirm(),
      started(forced),
      checkpoint(forced, '200'),
    )
    const plan = planPassFor(state(history), { force: false })
    expect(plan.force).toBe(true)
    expect(plan.resumeFrom).toBe(last)
  })

  it('resumes after a failed run from its committed cursor', () => {
    const [history, last] = ending(
      confirm(),
      started(unforced),
      failed(unforced, '300'),
    )
    expect(planPassFor(state(history), { force: false }).resumeFrom).toBe(last)
  })

  it('a failure before the first commit has no cursor to resume from', () => {
    expect(
      planPassFor(
        state([confirm(), started(unforced), failed(unforced, null)]),
        { force: false },
      ).resumeFrom,
    ).toBeNull()
  })

  it('a forced run never resumes an unforced pass', () => {
    expect(
      planPassFor(state([confirm(), started(unforced), checkpoint(unforced)]), {
        force: true,
      }).resumeFrom,
    ).toBeNull()
  })

  it('a completed pass is not resumed', () => {
    expect(
      planPassFor(state([confirm(), started(unforced), completed(unforced)]), {
        force: false,
      }).resumeFrom,
    ).toBeNull()
  })
})

describe('passProgress', () => {
  const progressOf = (history: MigrationStateRow[]) =>
    passProgress(deriveColumnMigration({ direction: 'reverse', history }))

  it.each([
    { name: 'nothing on record', history: () => [], expected: null },
    {
      name: 'awaiting the first run',
      history: () => [confirm()],
      expected: null,
    },
    {
      name: 'mid-pass, with the undecryptable rows skipped so far',
      history: () => [
        confirm(),
        ev(
          'decrypt_checkpoint',
          'decrypting',
          { ...unforced, rowsSkipped: 2 },
          { rowsProcessed: 40, rowsTotal: 100 },
        ),
      ],
      expected: {
        rowsProcessed: 40,
        rowsTotal: 100,
        rowsSkipped: 2,
        failed: false,
        completed: false,
      },
    },
    {
      name: 'a failed run shows where it stopped',
      history: () => [
        confirm(),
        ev('error', 'decrypting', unforced, {
          rowsProcessed: 10,
          rowsTotal: 100,
        }),
      ],
      expected: {
        rowsProcessed: 10,
        rowsTotal: 100,
        rowsSkipped: null,
        failed: true,
        completed: false,
      },
    },
    {
      name: 'complete',
      history: () => [
        confirm(),
        ev('decrypted', 'decrypted', unforced, {
          rowsProcessed: 100,
          rowsTotal: 100,
        }),
      ],
      expected: {
        rowsProcessed: 100,
        rowsTotal: 100,
        rowsSkipped: null,
        failed: false,
        completed: true,
      },
    },
    {
      name: 'a generated drop is past the pass',
      history: () => [confirm(), completed(unforced), dropGenerated()],
      expected: null,
    },
  ])('$name', ({ history, expected }) => {
    expect(progressOf(history())).toEqual(expected)
  })
})

describe('deriveTwinName', () => {
  it.each([
    {
      direction: 'reverse',
      column: 'email_encrypted',
      twin: 'email',
      via: 'convention',
    },
    {
      direction: 'reverse',
      column: '_encrypted',
      twin: '_encrypted_plaintext',
      via: 'fallback',
    },
    {
      direction: 'reverse',
      column: 'email_ct',
      twin: 'email_ct_plaintext',
      via: 'fallback',
    },
    {
      direction: 'forward',
      column: 'email',
      twin: 'email_encrypted',
      via: 'convention',
    },
  ] as const)(
    '$direction $column → $twin',
    ({ direction, column, twin, via }) => {
      expect(deriveTwinName(direction, column)).toEqual({ column: twin, via })
    },
  )
})

describe('manifestTwin', () => {
  const entry = (column: string, encryptedColumn?: string) => ({
    column,
    encryptedColumn,
    castAs: 'text' as const,
    indexes: [],
    targetPhase: 'cut-over' as const,
  })
  const manifest: Manifest = {
    version: 1,
    tables: {
      users: [entry('contact', 'email_encrypted'), entry('phone')],
    },
  }

  it.each([
    { direction: 'reverse', column: 'email_encrypted', twin: 'contact' },
    // An entry from before `encryptedColumn` was recorded: the convention.
    { direction: 'reverse', column: 'phone_encrypted', twin: 'phone' },
    { direction: 'reverse', column: 'contact_encrypted', twin: undefined },
    { direction: 'forward', column: 'contact', twin: 'email_encrypted' },
    { direction: 'forward', column: 'phone', twin: undefined },
  ] as const)('$direction $column → $twin', ({ direction, column, twin }) => {
    expect(manifestTwin(direction, manifest, 'users', column)).toBe(twin)
  })

  it('no manifest, or no entry for the table, names nothing', () => {
    expect(
      manifestTwin('reverse', null, 'users', 'email_encrypted'),
    ).toBeUndefined()
    expect(
      manifestTwin('reverse', manifest, 'orders', 'email_encrypted'),
    ).toBeUndefined()
  })
})

describe('the obligation and pass plan types', () => {
  it('admit only the states the rules produce', () => {
    // Checked by `tsc`: each assignment marked below would compile if the
    // fields were independent.
    const neverWaivable = { reason: 'forced-pass', waivable: true } as const
    const alwaysWaivable = {
      reason: 'existing-values',
      waivable: false,
    } as const
    const base = { kind: 'forced-pass', openedAt: null } as const
    // @ts-expect-error a forced-pass obligation is never waivable
    const a: Obligation = { ...base, ...neverWaivable }
    // @ts-expect-error an existing-values obligation is always waivable
    const b: Obligation = { ...base, ...alwaysWaivable }
    const unforced = { force: false, forcedBy: 'caller' } as const
    const forced = { force: true, forcedBy: null } as const
    // @ts-expect-error an unforced plan has no reason
    const c: PassPlan = { ...unforced, resumeFrom: null }
    // @ts-expect-error a forced plan always has one
    const d: PassPlan = { ...forced, resumeFrom: null }
    expect([a, b, c, d]).toHaveLength(4)

    const plan = planPassFor(
      deriveColumnMigration({ direction: 'reverse', history: [] }),
      { force: false },
    )
    if (plan.force) {
      expectTypeOf(plan.forcedBy).toEqualTypeOf<
        'caller' | Obligation['reason']
      >()
    } else {
      expectTypeOf(plan.forcedBy).toEqualTypeOf<null>()
    }
  })
})
