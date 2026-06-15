import { describe, expect, it } from 'vitest'
import { type V3Index, eqlV3Domain, v3CastAs } from '../../src/pg/v3/domain-map'

describe('eqlV3Domain', () => {
  it('maps text + each index to its capability domain', () => {
    expect(eqlV3Domain('text', undefined)).toBe('eql_v3.text')
    expect(eqlV3Domain('text', 'equality')).toBe('eql_v3.text_eq')
    expect(eqlV3Domain('text', 'freeTextSearch')).toBe('eql_v3.text_match')
    expect(eqlV3Domain('text', 'orderAndRange')).toBe('eql_v3.text_ord')
  })

  it('rejects out-of-scope dataTypes loudly', () => {
    // @ts-expect-error 'number' is not a v3 scalar in this milestone
    expect(() => eqlV3Domain('number', 'equality')).toThrow(
      /unsupported.*dataType.*number/i,
    )
    // @ts-expect-error 'boolean' has no v3 domain
    expect(() => eqlV3Domain('boolean', 'equality')).toThrow(/unsupported/i)
    // @ts-expect-error searchableJson is not a v3 index in this milestone
    expect(() => eqlV3Domain('text', 'searchableJson')).toThrow(/unsupported/i)
  })

  it('translates the text scalar to its internal CastAs', () => {
    expect(v3CastAs('text')).toBe('string')
  })
})
