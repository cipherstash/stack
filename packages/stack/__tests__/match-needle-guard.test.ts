import { describe, expect, it } from 'vitest'
import type { MatchIndexOpts } from '@/schema'
import { matchNeedleError, matchNeedleMinLength } from '@/schema/match-defaults'

// The floor a free-text needle must clear before it yields any ngram. A needle
// below it tokenizes to nothing, so its bloom filter is EMPTY — and
// `stored_bf @> '{}'` is true for every row. Such a query is unanswerable, not
// merely unmatched, so the guard must reject it rather than silently return the
// whole table.
const ngram: MatchIndexOpts = { tokenizer: { kind: 'ngram', token_length: 3 } }

describe('matchNeedleMinLength', () => {
  it('is the ngram tokenizer token_length', () => {
    expect(matchNeedleMinLength(ngram)).toBe(3)
    expect(
      matchNeedleMinLength({ tokenizer: { kind: 'ngram', token_length: 4 } }),
    ).toBe(4)
  })

  it('defaults an absent tokenizer to the schema default rather than skipping the floor', () => {
    expect(matchNeedleMinLength({})).toBe(3)
  })
})

describe('matchNeedleError', () => {
  it('accepts a needle at or above the floor', () => {
    expect(matchNeedleError('joh', ngram)).toBeUndefined()
    expect(matchNeedleError('lovelace', ngram)).toBeUndefined()
  })

  it('rejects a needle below the floor, naming the floor and the term', () => {
    expect(matchNeedleError('ad', ngram)).toMatch(/at least 3 characters/)
    expect(matchNeedleError('ad', ngram)).toMatch(/"ad"/)
  })

  // The tokenizer counts Unicode CODEPOINTS. `'👍👍'` is 2 codepoints but 4
  // UTF-16 code units, so a `needle.length` check waves it through — and it
  // then matches every row. Measured live: 3/3 rows returned.
  it('rejects an astral-plane needle below the floor in CODEPOINTS, not UTF-16 units', () => {
    expect('👍👍'.length).toBe(4) // pins why a naive length check passes it
    expect([...'👍👍'].length).toBe(2)

    expect(matchNeedleError('👍👍', ngram)).toMatch(/at least 3 characters/)
  })

  it('reports the codepoint count, not the UTF-16 length, in the message', () => {
    expect(matchNeedleError('👍👍', ngram)).toMatch(/has 2\b/)
  })

  it('accepts an astral-plane needle that reaches the floor in codepoints', () => {
    expect(matchNeedleError('👍👍👍', ngram)).toBeUndefined()
  })

  // Combining acute accents. NFD 'e\u0301e\u0301' is 4 codepoints but only 2
  // grapheme clusters, and (measured live) builds a NON-empty filter — so the
  // unit is codepoints, not graphemes. A grapheme floor would wrongly reject it.
  //
  // Built from explicit escapes: the PRECOMPOSED NFC form is a different string
  // of only 2 codepoints, which the guard correctly rejects. A bare literal here
  // would test whichever form the file happened to be normalised to on disk.
  const NFD_EE = 'e\u0301e\u0301'
  const NFC_EE = '\u00e9\u00e9'

  it('accepts a combining-accent needle that is 4 codepoints but only 2 graphemes', () => {
    expect([...NFD_EE].length).toBe(4)
    expect(matchNeedleError(NFD_EE, ngram)).toBeUndefined()
  })

  it('rejects the precomposed NFC form, which really is 2 codepoints', () => {
    expect([...NFC_EE].length).toBe(2)
    expect(matchNeedleError(NFC_EE, ngram)).toMatch(/at least 3 characters/)
  })

  it('rejects the empty needle whatever the tokenizer', () => {
    expect(matchNeedleError('', ngram)).toBeTypeOf('string')
    // A `standard` tokenizer imposes no ngram floor, but the empty string still
    // yields zero tokens and so still matches every row.
    expect(
      matchNeedleError('', { tokenizer: { kind: 'standard' } }),
    ).toBeTypeOf('string')
  })

  it('imposes no floor on a non-empty needle under a standard tokenizer', () => {
    expect(
      matchNeedleError('a', { tokenizer: { kind: 'standard' } }),
    ).toBeUndefined()
  })

  it('ignores non-string operands, leaving them to the encryption layer', () => {
    expect(matchNeedleError(42, ngram)).toBeUndefined()
    expect(matchNeedleError(null, ngram)).toBeUndefined()
  })
})
