import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { nextMoveHint, readProjectStatus } from '../index.js'
import {
  type ColumnObservation,
  buildColumnQuest,
  buildQuestLog,
  inferQuestPath,
  isComplete,
} from '../quest.js'
import {
  renderQuestLogJSON,
  renderQuestLogPlain,
  renderQuestLogTTY,
} from '../render.js'

// Use a non-npm runner everywhere so the tests fail loudly if any
// renderer or builder ever hard-codes `npx stash`. The exact value is
// arbitrary — what matters is that it is the value the caller passed,
// not a baked-in default.
const CLI = 'pnpm dlx stash'

let cwd: string

beforeEach(() => {
  cwd = mkdtempSync(join(tmpdir(), 'stash-status-'))
})

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true })
})

function writeContext(payload: Record<string, unknown>): void {
  mkdirSync(join(cwd, '.cipherstash'), { recursive: true })
  writeFileSync(
    join(cwd, '.cipherstash', 'context.json'),
    JSON.stringify(payload),
    'utf-8',
  )
}

const sampleContext = {
  cliVersion: '0.0.0',
  integration: 'drizzle' as const,
  encryptionClientPath: './src/encryption/index.ts',
  packageManager: 'pnpm' as const,
  installCommand: 'pnpm add @cipherstash/stack',
  envKeys: [],
  schemas: [
    { tableName: 'users', columns: [] },
    { tableName: 'orders', columns: [] },
  ],
  installedSkills: [],
  generatedAt: '2026-01-01T00:00:00.000Z',
}

describe('readProjectStatus', () => {
  it('reports a virgin project as uninitialized', () => {
    const status = readProjectStatus(cwd)
    expect(status.initialized).toBe(false)
    expect(status.planExists).toBe(false)
    expect(status.agentEngaged).toBe(false)
  })

  it('reports init-only state when only context.json exists', () => {
    writeContext(sampleContext)
    const status = readProjectStatus(cwd)
    expect(status.initialized).toBe(true)
    expect(status.context?.integration).toBe('drizzle')
    expect(status.planExists).toBe(false)
  })

  it('treats malformed context.json as not-initialized rather than throwing', () => {
    mkdirSync(join(cwd, '.cipherstash'), { recursive: true })
    writeFileSync(
      join(cwd, '.cipherstash', 'context.json'),
      '{ not json',
      'utf-8',
    )
    const status = readProjectStatus(cwd)
    expect(status.initialized).toBe(false)
  })
})

describe('inferQuestPath', () => {
  it('treats a column with no cs_migrations entry as new', () => {
    expect(
      inferQuestPath({ table: 't', column: 'c', phase: null, eql: null }),
    ).toBe('new')
  })

  it('treats a column with any cs_migrations history as migrate', () => {
    expect(
      inferQuestPath({
        table: 't',
        column: 'c',
        phase: 'dual-writing',
      }),
    ).toBe('migrate')
  })

  it('defaults to migrate when DB connectivity is missing', () => {
    expect(inferQuestPath({ table: 't', column: 'c' })).toBe('migrate')
  })
})

describe('buildColumnQuest — migrate path', () => {
  function obs(extra: Partial<ColumnObservation>): ColumnObservation {
    return { table: 'users', column: 'email', phase: null, eql: null, ...extra }
  }

  it('with no signals: 0/5, schema-add active, rest locked', () => {
    const quest = buildColumnQuest(
      { table: 'users', column: 'email', phase: null, eql: null },
      CLI,
    )
    expect(quest.path).toBe('new')
    // The schema-add objective should be the active one and every other
    // objective locked. Asserting per-objective status guards the no-
    // signal invariant against regressions in computeDoneCount.
    expect(quest.progress).toEqual({ done: 0, total: 2 })
    expect(quest.objectives[0].status).toBe('active')
    expect(quest.objectives[1].status).toBe('locked')
  })

  it('5-objective shape applies to any non-null migrate phase (sanity)', () => {
    // The migrate quest is always 5 objectives regardless of which phase
    // produced it. Kept as a separate sanity check rather than smuggled
    // into the no-signals test where it does not belong.
    const quest = buildColumnQuest(
      { table: 'users', column: 'email', phase: 'dual-writing' },
      CLI,
    )
    expect(quest.path).toBe('migrate')
    expect(quest.progress.total).toBe(5)
  })

  it('phase=null + EQL pending + twin exists: schema-add done (1/5), dual-writes deployed active', () => {
    const quest = buildColumnQuest(
      obs({
        phase: null,
        eql: { state: 'pending' },
        physicalEncryptedTwinExists: true,
      }),
      CLI,
    )
    expect(quest.path).toBe('migrate')
    expect(quest.progress).toEqual({ done: 1, total: 5 })
    expect(quest.objectives[0].status).toBe('done')
    expect(quest.objectives[1].status).toBe('active')
    expect(quest.objectives[2].status).toBe('locked')
  })

  it('phase=dual-writing: 2/5, backfill active', () => {
    const quest = buildColumnQuest(obs({ phase: 'dual-writing' }), CLI)
    expect(quest.progress).toEqual({ done: 2, total: 5 })
    expect(quest.objectives[1].status).toBe('done')
    expect(quest.objectives[2].status).toBe('active')
    expect(quest.objectives[2].label).toMatch(/backfill/i)
  })

  it('phase=backfilling counts as 2/5 (backfill in flight is still the active step)', () => {
    const quest = buildColumnQuest(obs({ phase: 'backfilling' }), CLI)
    expect(quest.progress.done).toBe(2)
    expect(quest.objectives[2].status).toBe('active')
  })

  it('phase=backfilled: 3/5, cutover active', () => {
    const quest = buildColumnQuest(obs({ phase: 'backfilled' }), CLI)
    expect(quest.progress.done).toBe(3)
    expect(quest.objectives[3].status).toBe('active')
    expect(quest.objectives[3].label).toMatch(/cut over/i)
  })

  it('phase=cut-over: 4/5, drop plaintext active', () => {
    const quest = buildColumnQuest(obs({ phase: 'cut-over' }), CLI)
    expect(quest.progress.done).toBe(4)
    expect(quest.objectives[4].status).toBe('active')
    expect(quest.objectives[4].label).toMatch(/drop plaintext/i)
  })

  it('phase=dropped: 5/5 (complete)', () => {
    const quest = buildColumnQuest(obs({ phase: 'dropped' }), CLI)
    expect(quest.progress).toEqual({ done: 5, total: 5 })
    expect(isComplete(quest)).toBe(true)
    expect(quest.nextMove).toBeUndefined()
  })

  it('next-move hint uses the caller-supplied runner and concrete --table/--column', () => {
    // Regression guard: the hint must be prefixed with whatever `cli` the
    // caller passed in (e.g. `pnpm dlx stash`), never a hard-coded
    // `npx stash` string.
    const backfill = buildColumnQuest(obs({ phase: 'dual-writing' }), CLI)
    expect(backfill.nextMove).toContain(`${CLI} encrypt backfill`)
    expect(backfill.nextMove).toContain('--table users')
    expect(backfill.nextMove).toContain('--column email')
    expect(backfill.nextMove).not.toContain('npx stash')

    const cutover = buildColumnQuest(obs({ phase: 'backfilled' }), CLI)
    expect(cutover.nextMove).toContain(`${CLI} encrypt cutover`)

    const drop = buildColumnQuest(obs({ phase: 'cut-over' }), CLI)
    expect(drop.nextMove).toContain(`${CLI} encrypt drop`)
  })

  it('falls back to physical-column existence as a schema-add signal', () => {
    const quest = buildColumnQuest(
      obs({
        phase: null,
        eql: null,
        physicalEncryptedTwinExists: true,
      }),
      CLI,
    )
    expect(quest.progress.done).toBe(1)
    expect(quest.objectives[0].status).toBe('done')
  })
})

describe('buildColumnQuest — new path', () => {
  it('no EQL config: 0/2, schema-add active', () => {
    const quest = buildColumnQuest(
      { table: 'orders', column: 'note', phase: null, eql: null },
      CLI,
    )
    expect(quest.path).toBe('new')
    expect(quest.progress).toEqual({ done: 0, total: 2 })
    expect(quest.objectives[0].status).toBe('active')
  })

  it('EQL pending: 1/2, activate active, hint uses caller-supplied runner', () => {
    const quest = buildColumnQuest(
      {
        table: 'orders',
        column: 'note',
        phase: null,
        eql: { state: 'pending' },
      },
      CLI,
    )
    expect(quest.progress).toEqual({ done: 1, total: 2 })
    expect(quest.objectives[1].status).toBe('active')
    expect(quest.nextMove).toContain(`${CLI} db activate`)
  })

  it('EQL active: 2/2, complete', () => {
    const quest = buildColumnQuest(
      {
        table: 'orders',
        column: 'note',
        phase: null,
        eql: { state: 'active' },
      },
      CLI,
    )
    expect(isComplete(quest)).toBe(true)
    expect(quest.nextMove).toBeUndefined()
  })
})

describe('buildColumnQuest — DB unreachable', () => {
  it('locks every objective except the first when phase and eql are both undefined', () => {
    const quest = buildColumnQuest({ table: 't', column: 'c' }, CLI)
    expect(quest.path).toBe('migrate')
    expect(quest.objectives[0].status).toBe('active')
    expect(quest.objectives.slice(1).every((o) => o.status === 'locked')).toBe(
      true,
    )
  })

  it('suppresses nextMove when DB is unreachable (do not invent a step)', () => {
    // Regression guard: a column actually mid-cutover whose DB is briefly
    // unreachable would otherwise be told to re-run schema-add via
    // nextMoveFor's doneCount=0 fallback. The renderer surfaces the
    // unreachable footer instead.
    const quest = buildColumnQuest({ table: 't', column: 'c' }, CLI)
    expect(quest.nextMove).toBeUndefined()
  })
})

describe('buildQuestLog', () => {
  it('separates active and completed quests', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [
        { table: 'users', column: 'email', phase: 'dropped' },
        { table: 'users', column: 'phone', phase: 'dual-writing' },
      ],
      cli: CLI,
    })
    expect(log.completed).toHaveLength(1)
    expect(log.completed[0].column).toBe('email')
    expect(log.active).toHaveLength(1)
    expect(log.active[0].column).toBe('phone')
  })

  it('reports observedFromDb=false when DB couldn’t be reached', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: false,
      observations: [{ table: 'users', column: 'email' }],
      cli: CLI,
    })
    expect(log.observedFromDb).toBe(false)
  })

  it('an empty observations list with initialized=true means the user has not declared columns yet', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [],
      cli: CLI,
    })
    expect(log.active).toEqual([])
    expect(log.completed).toEqual([])
  })
})

describe('renderQuestLogTTY', () => {
  it('shows an empty-state for uninitialized projects with init prompt that uses the caller-supplied runner', () => {
    const out = renderQuestLogTTY(
      buildQuestLog({
        initialized: false,
        observedFromDb: false,
        observations: [],
        cli: CLI,
      }),
      CLI,
    )
    expect(out).toMatch(/no quests yet/i)
    expect(out).toContain(`${CLI} init`)
    expect(out).toContain(`${CLI} plan`)
    expect(out).not.toContain('npx stash')
  })

  it('renders the active-quest section with progress bar, objectives, and next-move hint', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [
        { table: 'users', column: 'email', phase: 'dual-writing' },
      ],
      cli: CLI,
    })
    const out = renderQuestLogTTY(log, CLI)
    expect(out).toContain('CipherStash Quest Log')
    expect(out).toContain('ACTIVE QUEST')
    expect(out).toContain('Encrypt users.email')
    expect(out).toMatch(/2\/5 objectives/)
    expect(out).toContain('▓')
    expect(out).toContain('░')
    expect(out).toMatch(/← you are here/)
    expect(out).toMatch(/Next move/)
    // Quest-level next-move text uses the caller-supplied runner.
    expect(out).toContain(`${CLI} encrypt backfill`)
    expect(out).not.toContain('npx stash')
  })

  it('shows a 🏆 line per completed quest', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [{ table: 'users', column: 'ssn', phase: 'dropped' }],
      cli: CLI,
    })
    const out = renderQuestLogTTY(log, CLI)
    expect(out).toContain('🏆 COMPLETED')
    expect(out).toContain('users.ssn')
  })

  it('appends a DB-unreachable note when observedFromDb is false', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: false,
      observations: [{ table: 'users', column: 'email' }],
      cli: CLI,
    })
    const out = renderQuestLogTTY(log, CLI)
    expect(out).toMatch(/could not reach the database/i)
  })
})

describe('renderQuestLogPlain', () => {
  it('emits no emoji or progress-bar glyphs', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [
        { table: 'users', column: 'email', phase: 'dual-writing' },
      ],
      cli: CLI,
    })
    const out = renderQuestLogPlain(log, CLI)
    expect(out).not.toMatch(/⚔️|🏆|🔒|💡|▓|░/)
    expect(out).toContain('Encrypt users.email')
    expect(out).toMatch(/Progress: 2\/5/)
    expect(out).toContain('Next move:')
    expect(out).toContain(`${CLI} encrypt backfill`)
    expect(out).not.toContain('npx stash')
    // Bracketed status markers as a stable plain-text signal for scripts.
    expect(out).toMatch(/\[x\]/)
    expect(out).toMatch(/\[>\]/)
    expect(out).toMatch(/\[ \]/)
  })

  it('reports completed rollouts cleanly', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [{ table: 'users', column: 'ssn', phase: 'dropped' }],
      cli: CLI,
    })
    const out = renderQuestLogPlain(log, CLI)
    expect(out).toContain('Completed')
    expect(out).toContain('users.ssn')
    expect(out).not.toMatch(/🏆/)
  })

  it('empty-state hints use the caller-supplied runner', () => {
    const out = renderQuestLogPlain(
      buildQuestLog({
        initialized: false,
        observedFromDb: false,
        observations: [],
        cli: CLI,
      }),
      CLI,
    )
    expect(out).toContain(`${CLI} init`)
    expect(out).toContain(`${CLI} plan`)
    expect(out).not.toContain('npx stash')
  })
})

describe('renderQuestLogJSON', () => {
  it('emits a stable JSON shape with all fields a script needs', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [
        { table: 'users', column: 'email', phase: 'dual-writing' },
        { table: 'users', column: 'ssn', phase: 'dropped' },
      ],
      cli: CLI,
    })
    const json = renderQuestLogJSON(log)
    const parsed = JSON.parse(json)
    expect(parsed.initialized).toBe(true)
    expect(parsed.observedFromDb).toBe(true)
    expect(parsed.active).toHaveLength(1)
    expect(parsed.completed).toHaveLength(1)

    const active = parsed.active[0]
    expect(active.table).toBe('users')
    expect(active.column).toBe('email')
    expect(active.path).toBe('migrate')
    expect(active.progress).toEqual({ done: 2, total: 5 })
    expect(active.complete).toBe(false)
    expect(active.nextMove).toContain(`${CLI} encrypt backfill`)
    expect(Array.isArray(active.objectives)).toBe(true)
    expect(active.objectives[0]).toHaveProperty('label')
    expect(active.objectives[0]).toHaveProperty('status')
  })
})

describe('nextMoveHint', () => {
  it('points at init when uninitialized', () => {
    const log = buildQuestLog({
      initialized: false,
      observedFromDb: false,
      observations: [],
      cli: CLI,
    })
    expect(nextMoveHint(log, CLI)).toMatch(/init/)
  })

  it('points at plan when initialized but no quests', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [],
      cli: CLI,
    })
    expect(nextMoveHint(log, CLI)).toMatch(/plan/)
  })

  it('uses the first active quest’s nextMove when one exists', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [
        { table: 'users', column: 'email', phase: 'dual-writing' },
      ],
      cli: CLI,
    })
    expect(nextMoveHint(log, CLI)).toContain(`${CLI} encrypt backfill`)
  })

  it('reports complete when every quest is done', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [{ table: 'users', column: 'ssn', phase: 'dropped' }],
      cli: CLI,
    })
    expect(nextMoveHint(log, CLI)).toMatch(/complete|nothing/i)
  })
})
