import { describe, expect, it } from 'vitest'
import {
  CIPHERSTASH_CODEC_ID_SET,
  CIPHERSTASH_CODEC_TRAITS,
  CIPHERSTASH_STRING_CODEC_ID,
  CIPHERSTASH_STRING_V3_CODEC_ID,
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
  CIPHERSTASH_TRAIT_STRING,
  CIPHERSTASH_V3_CODEC_ID_SET,
  EQL_V3_SCHEMA,
  isCipherstashV3CodecId,
} from '../../src/extension-metadata/constants'

describe('v3 constants', () => {
  it('defines the v3 string codec id and schema', () => {
    expect(CIPHERSTASH_STRING_V3_CODEC_ID).toBe('cipherstash/string-v3@1')
    expect(EQL_V3_SCHEMA).toBe('eql_v3')
  })
  it('keeps v3 ids OUT of the v2 set (so the v2 middleware ignores them)', () => {
    expect(CIPHERSTASH_CODEC_ID_SET.has(CIPHERSTASH_STRING_V3_CODEC_ID)).toBe(false)
    expect(CIPHERSTASH_V3_CODEC_ID_SET.has(CIPHERSTASH_STRING_V3_CODEC_ID)).toBe(true)
  })
  it('guards v3 codec ids', () => {
    expect(isCipherstashV3CodecId(CIPHERSTASH_STRING_V3_CODEC_ID)).toBe(true)
    expect(isCipherstashV3CodecId(CIPHERSTASH_STRING_CODEC_ID)).toBe(false)
  })
  it('defines the shared string trait (for the legacy eq/ilike single-trait dispatch)', () => {
    expect(CIPHERSTASH_TRAIT_STRING).toBe('cipherstash:string')
  })
  it('carries cipherstash:string on BOTH string codecs, NOT on numeric/bool codecs', () => {
    expect(CIPHERSTASH_CODEC_TRAITS[CIPHERSTASH_STRING_CODEC_ID]).toContain(CIPHERSTASH_TRAIT_STRING)
    expect(CIPHERSTASH_CODEC_TRAITS[CIPHERSTASH_STRING_V3_CODEC_ID]).toContain(CIPHERSTASH_TRAIT_STRING)
    // double/bigint/date/boolean must NOT carry it (preserves v2 eq/ilike string-only visibility)
    expect(CIPHERSTASH_CODEC_TRAITS['cipherstash/double@1'] ?? []).not.toContain(CIPHERSTASH_TRAIT_STRING)
  })
  it('v3 codec carries the v2 cipherstash traits so existing single-trait operators attach', () => {
    const t = CIPHERSTASH_CODEC_TRAITS[CIPHERSTASH_STRING_V3_CODEC_ID] ?? []
    expect(t).toEqual(
      expect.arrayContaining([
        CIPHERSTASH_TRAIT_STRING,
        CIPHERSTASH_TRAIT_EQUALITY,
        CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
        CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      ]),
    )
  })
})
