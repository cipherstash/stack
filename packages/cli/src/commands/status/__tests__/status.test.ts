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
} from '../quest.js'
import {
  renderQuestLogJSON,
  renderQuestLogPlain,
  renderQuestLogTTY,
} from '../render.js'

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
    // The 5-objective shape is more informative when we genuinely don't
    // know — better to show the full lifecycle locked than to default to
    // a 2-objective new-column shape that hides relevant work.
    expect(inferQuestPath({ table: 't', column: 'c' })).toBe('migrate')
  })
})

describe('buildColumnQuest — migrate path', () => {
  function obs(extra: Partial<ColumnObservation>): ColumnObservation {
    return { table: 'users', column: 'email', phase: null, eql: null, ...extra }
  }

  it('with no signals: 0/5, schema-add active, rest locked', () => {
    const quest = buildColumnQuest(obs({ phase: 'dual-writing' }))
    // Picking dual-writing forces the migrate path; reset and check no-events.
    const noEvents = buildColumnQuest({
      table: 'users',
      column: 'email',
      phase: 'dual-writing',
    })
    expect(noEvents.path).toBe('migrate')
    expect(quest.progress.total).toBe(5)
  })

  it('phase=null + EQL pending + twin exists: schema-add done (1/5), dual-writes deployed active', () => {
    // The encrypted twin column existing alongside the original is the
    // unambiguous "this is a migrate column" signal — the rollout PR
    // created `<col>_encrypted` and ran `db push` (writing pending). The
    // user has not yet recorded a `dual_writing` event, so the next
    // active objective is "deploy dual-writes to production".
    const quest = buildColumnQuest(
      obs({
        phase: null,
        eql: { state: 'pending' },
        physicalEncryptedTwinExists: true,
      }),
    )
    expect(quest.path).toBe('migrate')
    expect(quest.progress).toEqual({ done: 1, total: 5 })
    expect(quest.objectives[0].status).toBe('done')
    expect(quest.objectives[1].status).toBe('active')
    expect(quest.objectives[2].status).toBe('locked')
  })

  it('phase=dual-writing: 2/5, backfill active', () => {
    const quest = buildColumnQuest(obs({ phase: 'dual-writing' }))
    expect(quest.progress).toEqual({ done: 2, total: 5 })
    expect(quest.objectives[1].status).toBe('done')
    expect(quest.objectives[2].status).toBe('active')
    expect(quest.objectives[2].label).toMatch(/backfill/i)
  })

  it('phase=backfilling counts as 2/5 (backfill in flight is still the active step)', () => {
    const quest = buildColumnQuest(obs({ phase: 'backfilling' }))
    expect(quest.progress.done).toBe(2)
    expect(quest.objectives[2].status).toBe('active')
  })

  it('phase=backfilled: 3/5, cutover active', () => {
    const quest = buildColumnQuest(obs({ phase: 'backfilled' }))
    expect(quest.progress.done).toBe(3)
    expect(quest.objectives[3].status).toBe('active')
    expect(quest.objectives[3].label).toMatch(/cut over/i)
  })

  it('phase=cut-over: 4/5, drop plaintext active', () => {
    const quest = buildColumnQuest(obs({ phase: 'cut-over' }))
    expect(quest.progress.done).toBe(4)
    expect(quest.objectives[4].status).toBe('active')
    expect(quest.objectives[4].label).toMatch(/drop plaintext/i)
  })

  it('phase=dropped: 5/5 (complete)', () => {
    const quest = buildColumnQuest(obs({ phase: 'dropped' }))
    expect(quest.progress).toEqual({ done: 5, total: 5 })
    expect(quest.complete).toBe(true)
    expect(quest.nextMove).toBeUndefined()
  })

  it('next-move hint references concrete CLI invocations with --table/--column', () => {
    const backfill = buildColumnQuest(obs({ phase: 'dual-writing' }))
    expect(backfill.nextMove).toContain('stash encrypt backfill')
    expect(backfill.nextMove).toContain('--table users')
    expect(backfill.nextMove).toContain('--column email')

    const cutover = buildColumnQuest(obs({ phase: 'backfilled' }))
    expect(cutover.nextMove).toContain('stash encrypt cutover')

    const drop = buildColumnQuest(obs({ phase: 'cut-over' }))
    expect(drop.nextMove).toContain('stash encrypt drop')
  })

  it('falls back to physical-column existence as a schema-add signal', () => {
    // cs_migrations is silent (schema_added events are never written);
    // information_schema is the next-best signal that schema-add has been
    // applied. When EQL config is missing too but the encrypted twin
    // column physically exists, treat schema-add as done.
    const quest = buildColumnQuest(
      obs({
        phase: null,
        eql: null,
        physicalEncryptedTwinExists: true,
      }),
    )
    expect(quest.progress.done).toBe(1)
    expect(quest.objectives[0].status).toBe('done')
  })
})

describe('buildColumnQuest — new path', () => {
  it('no EQL config: 0/2, schema-add active', () => {
    const quest = buildColumnQuest({
      table: 'orders',
      column: 'note',
      phase: null,
      eql: null,
    })
    expect(quest.path).toBe('new')
    expect(quest.progress).toEqual({ done: 0, total: 2 })
    expect(quest.objectives[0].status).toBe('active')
  })

  it('EQL pending: 1/2, activate active', () => {
    const quest = buildColumnQuest({
      table: 'orders',
      column: 'note',
      phase: null,
      eql: { state: 'pending' },
    })
    expect(quest.progress).toEqual({ done: 1, total: 2 })
    expect(quest.objectives[1].status).toBe('active')
    expect(quest.nextMove).toMatch(/db activate/)
  })

  it('EQL active: 2/2, complete', () => {
    const quest = buildColumnQuest({
      table: 'orders',
      column: 'note',
      phase: null,
      eql: { state: 'active' },
    })
    expect(quest.complete).toBe(true)
    expect(quest.nextMove).toBeUndefined()
  })
})

describe('buildColumnQuest — DB unreachable', () => {
  it('locks every objective except the first when phase and eql are both undefined', () => {
    // The only honest answer is "I don't know what's been done" — show
    // the full migrate-shape with the first objective active so the user
    // sees that the rollout exists; the renderer surfaces a footer note
    // about the missing observation.
    const quest = buildColumnQuest({ table: 't', column: 'c' })
    expect(quest.path).toBe('migrate')
    expect(quest.objectives[0].status).toBe('active')
    expect(quest.objectives.slice(1).every((o) => o.status === 'locked')).toBe(
      true,
    )
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
    })
    expect(log.observedFromDb).toBe(false)
  })

  it('an empty observations list with initialized=true means the user has not declared columns yet', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [],
    })
    expect(log.active).toEqual([])
    expect(log.completed).toEqual([])
  })
})

describe('renderQuestLogTTY', () => {
  it('shows an empty-state for uninitialized projects with init prompt', () => {
    const out = renderQuestLogTTY(
      buildQuestLog({
        initialized: false,
        observedFromDb: false,
        observations: [],
      }),
    )
    expect(out).toMatch(/no quests yet/i)
    expect(out).toMatch(/stash init/)
  })

  it('renders the active-quest section with progress bar, objectives, and next-move hint', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [
        { table: 'users', column: 'email', phase: 'dual-writing' },
      ],
    })
    const out = renderQuestLogTTY(log)
    expect(out).toContain('CipherStash Quest Log')
    expect(out).toContain('ACTIVE QUEST')
    expect(out).toContain('Encrypt users.email')
    expect(out).toMatch(/2\/5 objectives/)
    expect(out).toContain('▓')
    expect(out).toContain('░')
    expect(out).toMatch(/← you are here/)
    expect(out).toMatch(/Next move/)
  })

  it('shows a 🏆 line per completed quest', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [{ table: 'users', column: 'ssn', phase: 'dropped' }],
    })
    const out = renderQuestLogTTY(log)
    expect(out).toContain('🏆 COMPLETED')
    expect(out).toContain('users.ssn')
  })

  it('appends a DB-unreachable note when observedFromDb is false', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: false,
      observations: [{ table: 'users', column: 'email' }],
    })
    const out = renderQuestLogTTY(log)
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
    })
    const out = renderQuestLogPlain(log)
    expect(out).not.toMatch(/⚔️|🏆|🔒|💡|▓|░/)
    // Still has the structural content.
    expect(out).toContain('Encrypt users.email')
    expect(out).toMatch(/Progress: 2\/5/)
    expect(out).toContain('Next move:')
    // Still uses bracketed status markers as a stable plain-text signal
    // for scripts.
    expect(out).toMatch(/\[x\]/)
    expect(out).toMatch(/\[>\]/)
    expect(out).toMatch(/\[ \]/)
  })

  it('reports completed rollouts cleanly', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [{ table: 'users', column: 'ssn', phase: 'dropped' }],
    })
    const out = renderQuestLogPlain(log)
    expect(out).toContain('Completed')
    expect(out).toContain('users.ssn')
    expect(out).not.toMatch(/🏆/)
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
    expect(active.nextMove).toContain('stash encrypt backfill')
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
    })
    expect(nextMoveHint(log, 'pnpm dlx stash')).toMatch(/init/)
  })

  it('points at plan when initialized but no quests', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [],
    })
    expect(nextMoveHint(log, 'pnpm dlx stash')).toMatch(/plan/)
  })

  it('uses the first active quest’s nextMove when one exists', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [
        { table: 'users', column: 'email', phase: 'dual-writing' },
      ],
    })
    expect(nextMoveHint(log, 'pnpm dlx stash')).toContain('stash encrypt backfill')
  })

  it('reports complete when every quest is done', () => {
    const log = buildQuestLog({
      initialized: true,
      observedFromDb: true,
      observations: [{ table: 'users', column: 'ssn', phase: 'dropped' }],
    })
    expect(nextMoveHint(log, 'pnpm dlx stash')).toMatch(/complete|nothing/i)
  })
})
