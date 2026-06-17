import { describe, expect, it } from 'vitest'
import { dialectForCodecId, v2Dialect, v3Dialect } from '../../src/execution/dialect'
import {
  CIPHERSTASH_STRING_CODEC_ID,
  CIPHERSTASH_STRING_V3_CODEC_ID,
} from '../../src/extension-metadata/constants'

describe('v2Dialect (must match current operators.ts templates byte-for-byte)', () => {
  it('equality / comparison / range / match / orderBy', () => {
    expect(v2Dialect.equality('eq')).toBe('eql_v2.eq({{self}}, {{arg0}})')
    expect(v2Dialect.equality('ne')).toBe('NOT eql_v2.eq({{self}}, {{arg0}})')
    expect(v2Dialect.comparison('gt')).toBe('eql_v2.gt({{self}}, {{arg0}})')
    expect(v2Dialect.comparison('gte')).toBe('eql_v2.gte({{self}}, {{arg0}})')
    expect(v2Dialect.comparison('lt')).toBe('eql_v2.lt({{self}}, {{arg0}})')
    expect(v2Dialect.comparison('lte')).toBe('eql_v2.lte({{self}}, {{arg0}})')
    expect(v2Dialect.range()).toBe('eql_v2.gte({{self}}, {{arg0}}) AND eql_v2.lte({{self}}, {{arg1}})')
    expect(v2Dialect.match('like')).toBe('eql_v2.ilike({{self}}, {{arg0}})')
  })
})

describe('v3Dialect (extracted-index-term form, mirrors drizzle v3Dialect)', () => {
  it('equality', () => {
    expect(v3Dialect.equality('eq')).toBe('eql_v3.eq_term({{self}}) = eql_v3.hmac_256({{arg0}}::jsonb)')
    expect(v3Dialect.equality('ne')).toBe('eql_v3.eq_term({{self}}) <> eql_v3.hmac_256({{arg0}}::jsonb)')
  })
  it('comparison — all four ord symbols distinct (catches gte→> copy-paste)', () => {
    expect(v3Dialect.comparison('gt')).toBe('eql_v3.ord_term({{self}}) > eql_v3.ore_block_u64_8_256({{arg0}}::jsonb)')
    expect(v3Dialect.comparison('gte')).toBe('eql_v3.ord_term({{self}}) >= eql_v3.ore_block_u64_8_256({{arg0}}::jsonb)')
    expect(v3Dialect.comparison('lt')).toBe('eql_v3.ord_term({{self}}) < eql_v3.ore_block_u64_8_256({{arg0}}::jsonb)')
    expect(v3Dialect.comparison('lte')).toBe('eql_v3.ord_term({{self}}) <= eql_v3.ore_block_u64_8_256({{arg0}}::jsonb)')
  })
  it('range / match', () => {
    expect(v3Dialect.range()).toBe(
      'eql_v3.ord_term({{self}}) >= eql_v3.ore_block_u64_8_256({{arg0}}::jsonb) AND ' +
        'eql_v3.ord_term({{self}}) <= eql_v3.ore_block_u64_8_256({{arg1}}::jsonb)',
    )
    expect(v3Dialect.match('like')).toBe('eql_v3.match_term({{self}}) @> eql_v3.bloom_filter({{arg0}}::jsonb)')
  })
})

describe('dialectForCodecId', () => {
  it('routes v2 ids to v2Dialect and v3 ids to v3Dialect', () => {
    expect(dialectForCodecId(CIPHERSTASH_STRING_CODEC_ID)).toBe(v2Dialect)
    expect(dialectForCodecId(CIPHERSTASH_STRING_V3_CODEC_ID)).toBe(v3Dialect)
  })
})
