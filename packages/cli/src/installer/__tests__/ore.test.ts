import { describe, expect, it } from 'vitest'
import { bundledExpectedSurface } from '@/installer/verify.js'
import {
  classifyOreState,
  describeOreCreatable,
  describeOreState,
  ORE_FALLBACK_REMEDY,
  ORE_OPCLASS_PRESENT_EXPR,
  type OreSurfaceState,
} from '../ore.js'

/**
 * The shared ORE model (#891). These assertions are about the *copy* as much
 * as the logic: the whole point of the module is that `eql preflight`,
 * `eql install`, `eql status` and `eql verify` say one thing about ORE, and
 * that the thing they say names a remedy a schema author can actually type.
 */
describe('classifyOreState', () => {
  const expectedPoisoned = 20

  it('reads a privileged install as indexable', () => {
    expect(
      classifyOreState({
        opclassPresent: true,
        poisonedDomains: 0,
        expectedPoisoned,
      }),
    ).toBe('indexable')
  })

  it('reads the managed-Postgres skip with a full fallback as fallback', () => {
    expect(
      classifyOreState({
        opclassPresent: false,
        poisonedDomains: expectedPoisoned,
        expectedPoisoned,
      }),
    ).toBe('fallback')
  })

  it('reads a partial fallback as incoherent, not as the supported skip', () => {
    expect(
      classifyOreState({
        opclassPresent: false,
        poisonedDomains: expectedPoisoned - 1,
        expectedPoisoned,
      }),
    ).toBe('incoherent-unpoisoned')
  })

  it('reads leftover poison alongside a present opclass as incoherent', () => {
    expect(
      classifyOreState({
        opclassPresent: true,
        poisonedDomains: 1,
        expectedPoisoned,
      }),
    ).toBe('incoherent-poisoned')
  })
})

describe('describeOreState', () => {
  it('treats both healthy states as info and both incoherent ones as damage', () => {
    expect(describeOreState('indexable').severity).toBe('info')
    expect(describeOreState('fallback').severity).toBe('info')
    expect(describeOreState('incoherent-poisoned').severity).toBe('damage')
    expect(describeOreState('incoherent-unpoisoned').severity).toBe('damage')
  })

  it('names the consequence and the remedy on the fallback path', () => {
    const { message } = describeOreState('fallback')
    // The consequence: not a failed install.
    expect(message).toContain('not a failed install')
    // The remedy, in the words a schema author types.
    expect(message).toContain('types.*Ord')
    expect(message).toContain(ORE_FALLBACK_REMEDY)
  })

  /**
   * The bundle creates `public.eql_v3_<t>_ord_ope` domains, but
   * `@cipherstash/stack` ships no `types.*OrdOpe` factory — so naming the
   * `_ord_ope` domains as the remedy sends a schema author to a column type
   * they cannot declare. This is the regression that guard exists for.
   */
  it('does not point a schema author at the factory-less `_ord_ope` domains', () => {
    const states: OreSurfaceState[] = [
      'indexable',
      'fallback',
      'incoherent-poisoned',
      'incoherent-unpoisoned',
    ]
    for (const state of states) {
      expect(describeOreState(state).message).not.toContain('_ord_ope')
      expect(describeOreState(state).message).not.toContain('OrdOpe')
    }
  })

  it('gives every state a short value for a report row', () => {
    expect(describeOreState('indexable').value).toBe('present')
    expect(describeOreState('fallback').value).toContain('skipped')
    expect(describeOreState('incoherent-poisoned').value).toBe('INCOHERENT')
  })
})

describe('describeOreCreatable', () => {
  it('annotates only the "no" answer, and never as a blocker', () => {
    expect(describeOreCreatable(true)).toEqual({ value: 'creatable' })
    const no = describeOreCreatable(false)
    expect(no.value).toBe('not creatable')
    expect(no.annotation).toContain('<- skips:')
    expect(no.annotation).not.toContain('<- blocks')
  })

  it('renders an unanswerable probe as its own third state', () => {
    const unknown = describeOreCreatable(null)
    expect(unknown.value).toBe('unknown')
    expect(unknown.annotation).toContain('stash eql verify')
  })
})

describe('ORE_OPCLASS_PRESENT_EXPR', () => {
  /**
   * `to_regtype` (not a `::regtype` cast) is what lets the expression return
   * `false` on a database with no EQL installed instead of raising — the
   * not-installed case is detected and reported separately by every caller.
   */
  it('degrades rather than raises on a database with no EQL', () => {
    expect(ORE_OPCLASS_PRESENT_EXPR).toContain('to_regtype')
    expect(ORE_OPCLASS_PRESENT_EXPR).not.toContain('::regtype')
  })

  it('probes the default btree opclass over the ORE block type', () => {
    expect(ORE_OPCLASS_PRESENT_EXPR).toContain('eql_v3_internal.ore_block_256')
    expect(ORE_OPCLASS_PRESENT_EXPR).toContain('c.opcdefault')
    expect(ORE_OPCLASS_PRESENT_EXPR).toContain(`am.amname = 'btree'`)
  })
})

describe('the expected-poison count', () => {
  /**
   * `describeOreState('fallback')` claims *every* ORE domain carries the
   * fallback. That claim is only meaningful if the set it is counted against
   * comes from the bundle, so pin the derivation rather than the prose.
   */
  it('is derived from the pinned bundle, not hand-maintained', () => {
    const { oreDomains } = bundledExpectedSurface()
    expect(oreDomains.length).toBeGreaterThan(0)
    for (const domain of oreDomains) expect(domain).toMatch(/_ore$/)
  })
})
