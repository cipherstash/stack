import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { ALL_V3_DOMAINS, eqlV3Domain, v3CastAs } from '../../src/v3/domain-map'

describe('eqlV3Domain', () => {
  it('maps the text scalar + index to a domain', () => {
    expect(eqlV3Domain('text', undefined)).toBe('eql_v3.text')
    expect(eqlV3Domain('text', 'equality')).toBe('eql_v3.text_eq')
    expect(eqlV3Domain('text', 'freeTextSearch')).toBe('eql_v3.text_match')
    expect(eqlV3Domain('text', 'orderAndRange')).toBe('eql_v3.text_ord')
  })
  it('rejects unsupported scalars/indexes', () => {
    // @ts-expect-error invalid scalar
    expect(() => eqlV3Domain('int', 'equality')).toThrow()
    // @ts-expect-error invalid index
    expect(() => eqlV3Domain('text', 'nope')).toThrow()
  })
})

describe('v3CastAs', () => {
  it('translates the text scalar to the protect CastAs', () => {
    // 'string' is the only supported cast in this milestone (text scalar only).
    expect(v3CastAs('text')).toBe('string')
  })
})

describe('ALL_V3_DOMAINS', () => {
  it('contains every text domain', () => {
    for (const d of ['eql_v3.text', 'eql_v3.text_eq', 'eql_v3.text_match', 'eql_v3.text_ord'])
      expect(ALL_V3_DOMAINS.has(d)).toBe(true)
  })
})

// Property: eqlV3Domain is total over the declared (scalar, index) space and
// always returns a member of ALL_V3_DOMAINS — catches a future scalar/index
// addition that forgets to register a domain.
describe('eqlV3Domain totality (property)', () => {
  it('every valid (text, index|undefined) maps into ALL_V3_DOMAINS', () => {
    fc.assert(
      fc.property(fc.constantFrom('equality', 'freeTextSearch', 'orderAndRange', undefined), (idx) => {
        expect(ALL_V3_DOMAINS.has(eqlV3Domain('text', idx as never))).toBe(true)
      }),
    )
  })
})
