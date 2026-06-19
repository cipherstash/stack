import type { MigrationPhase } from '@cipherstash/migrate'
import { describe, expect, it } from 'vitest'
import {
  type ColumnState,
  classifyPhase,
  classifyPhases,
  rollupPlanStep,
} from '../rollout-state.js'

describe('classifyPhase', () => {
  it('null phase classifies as unknown', () => {
    // No cs_migrations entry — brand new column or not yet started. The
    // caller has to ask the user before drafting a plan because we can't
    // tell new from migrate from disk alone.
    expect(classifyPhase(null)).toBe('unknown')
  })

  it('schema-added classifies as rollout', () => {
    // Synthesised by some renderers; mapping is "deploy gate not crossed".
    expect(classifyPhase('schema-added')).toBe('rollout')
  })

  it('dual-writing classifies as cutover', () => {
    // Once dual-writing is recorded, the deploy gate is crossed and the
    // remaining work is the cutover plan.
    expect(classifyPhase('dual-writing')).toBe('cutover')
  })

  it.each([
    'backfilling',
    'backfilled',
    'cut-over',
  ] as MigrationPhase[])('%s classifies as cutover (mid-cutover work)', (phase) => {
    expect(classifyPhase(phase)).toBe('cutover')
  })

  it('dropped classifies as completed', () => {
    expect(classifyPhase('dropped')).toBe('completed')
  })
})

describe('classifyPhases', () => {
  it('returns one state per requested column', () => {
    const states = classifyPhases(
      [
        { table: 'users', column: 'email' },
        { table: 'users', column: 'phone' },
        { table: 'orders', column: 'note' },
      ],
      (table, column) => {
        if (table === 'users' && column === 'email') return 'dual-writing'
        if (table === 'users' && column === 'phone') return 'cut-over'
        return null
      },
    )

    expect(states).toHaveLength(3)
    expect(states[0]).toEqual({
      table: 'users',
      column: 'email',
      phase: 'dual-writing',
      needs: 'cutover',
    })
    expect(states[1]).toEqual({
      table: 'users',
      column: 'phone',
      phase: 'cut-over',
      needs: 'cutover',
    })
    expect(states[2]).toEqual({
      table: 'orders',
      column: 'note',
      phase: null,
      needs: 'unknown',
    })
  })
})

describe('rollupPlanStep', () => {
  function state(needs: ColumnState['needs']): ColumnState {
    return { table: 't', column: 'c', phase: null, needs }
  }

  it('returns unknown for an empty list', () => {
    expect(rollupPlanStep([])).toBe('unknown')
  })

  it('returns cutover when any column needs cutover (mixed wins toward cutover)', () => {
    // The bias is deliberate. Once the user has crossed the deploy gate
    // for any column, they have already done the in-app dual-write work.
    // The cutover-plan template handles the mixed case explicitly so the
    // user doesn't have to do two plans in a row.
    expect(rollupPlanStep([state('rollout'), state('cutover')])).toBe('cutover')
  })

  it('returns rollout when columns are mixed rollout + unknown', () => {
    // No cutover-ready columns. Plan the rollout; the agent will resolve
    // the unknowns as it goes (asking the user about new vs migrate).
    expect(rollupPlanStep([state('rollout'), state('unknown')])).toBe('rollout')
  })

  it('returns rollout when every column needs rollout', () => {
    expect(rollupPlanStep([state('rollout'), state('rollout')])).toBe('rollout')
  })

  it('returns unknown when every column is unknown', () => {
    // Caller (e.g. `stash plan`) interprets this as "ask the user which
    // path applies before drafting".
    expect(rollupPlanStep([state('unknown'), state('unknown')])).toBe('unknown')
  })

  it('returns completed only when every column is completed', () => {
    expect(rollupPlanStep([state('completed'), state('completed')])).toBe(
      'completed',
    )
    expect(rollupPlanStep([state('completed'), state('cutover')])).toBe(
      'cutover',
    )
  })
})
