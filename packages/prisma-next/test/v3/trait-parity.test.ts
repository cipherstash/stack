/**
 * Guards against v2/v3 string trait-set drift.
 *
 * The legacy single-trait operators (`cipherstashEq` / `cipherstashIlike`)
 * dispatch on the shared `cipherstash:string` trait carried by BOTH string
 * codecs. If a future edit adds/removes the trait on one codec without the
 * other, eq/ilike would silently stop surfacing on that column. These
 * assertions read the real constants so such a drift fails here.
 */
import { describe, expect, it } from 'vitest'
import {
  CIPHERSTASH_CODEC_TRAITS,
  CIPHERSTASH_STRING_CODEC_ID,
  CIPHERSTASH_STRING_V3_CODEC_ID,
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
  CIPHERSTASH_TRAIT_STRING,
} from '../../src/extension-metadata/constants'

const v2 = CIPHERSTASH_CODEC_TRAITS[CIPHERSTASH_STRING_CODEC_ID] ?? []
const v3 = CIPHERSTASH_CODEC_TRAITS[CIPHERSTASH_STRING_V3_CODEC_ID] ?? []

describe('v2/v3 string trait parity', () => {
  it('both string codecs carry the shared cipherstash:string trait', () => {
    // Single-trait dispatch for cipherstashEq/cipherstashIlike depends on this.
    expect(v2).toContain(CIPHERSTASH_TRAIT_STRING)
    expect(v3).toContain(CIPHERSTASH_TRAIT_STRING)
  })

  it('the v3 string codec additionally carries equality, order-and-range, and free-text-search', () => {
    expect(v3).toContain(CIPHERSTASH_TRAIT_EQUALITY)
    expect(v3).toContain(CIPHERSTASH_TRAIT_ORDER_AND_RANGE)
    expect(v3).toContain(CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH)
  })

  it('the v2 and v3 string codecs advertise the same string-search trait set', () => {
    // The intended relationship: v3 reuses the full v2 string trait set, so a
    // change to one without the other (e.g. dropping order-and-range from only
    // the v2 codec) fails this assertion.
    const sortedV2 = [...v2].sort()
    const sortedV3 = [...v3].sort()
    expect(sortedV3).toEqual(sortedV2)
    expect(sortedV2).toEqual(
      [
        CIPHERSTASH_TRAIT_STRING,
        CIPHERSTASH_TRAIT_EQUALITY,
        CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
        CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      ].sort(),
    )
  })
})
