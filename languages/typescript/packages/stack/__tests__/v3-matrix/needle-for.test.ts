import { needleFor } from '@cipherstash/test-kit'
import { describe, expect, it } from 'vitest'
import { matchNeedleError } from '@/schema/match-defaults'
import { V3_MATRIX } from './catalog'

const MATCH_BLOCK = { tokenizer: { kind: 'ngram', token_length: 3 } } as const

const specWith = (samples: readonly unknown[]) =>
  ({ samples, indexes: { match: MATCH_BLOCK } }) as never

describe('needleFor', () => {
  // The guard counts codepoints; a UTF-16 `.length` check would wave '👍👍'
  // through (4 code units, 2 codepoints) and the `contains` test would then
  // fail inside the production guard, pointing at the wrong line.
  it('skips an astral sample that the production guard would reject', () => {
    expect(needleFor(specWith(['👍👍', 'ada@example.com']))).toBe(
      'ada@example.com',
    )
  })

  it('skips the empty sample', () => {
    expect(needleFor(specWith(['', 'Ada Lovelace']))).toBe('Ada Lovelace')
  })

  it('skips non-string samples', () => {
    expect(needleFor(specWith([42, null, 'Ada']))).toBe('Ada')
  })

  it('throws when no sample can be searched', () => {
    expect(() => needleFor(specWith(['', 'ab', '👍👍']))).toThrow(
      /no searchable sample/,
    )
  })

  it('honours a larger token_length', () => {
    const spec = {
      samples: ['ada', 'adam'],
      indexes: { match: { tokenizer: { kind: 'ngram', token_length: 4 } } },
    } as never
    expect(needleFor(spec)).toBe('adam')
  })

  // The contract that matters: whatever it picks, the guard must accept.
  it('never returns a needle the guard rejects, across every match domain', () => {
    const matchDomains = Object.values(V3_MATRIX).filter(
      (spec) => spec.indexes.match,
    )
    expect(matchDomains.length).toBeGreaterThan(0)

    for (const spec of matchDomains) {
      const needle = needleFor(spec)
      expect(matchNeedleError(needle, spec.indexes.match ?? {})).toBeUndefined()
    }
  })
})
