import { describe, expect, it } from 'vitest'
import { parseLikeNeedle } from '../src/like-pattern'

/**
 * Direct unit coverage for `parseLikeNeedle`.
 *
 * The function is the whole of the like/ilike → matches() approximation: it
 * decides which patterns are delegable and what literal term the encrypted
 * fuzzy search actually receives. Its only other coverage is two end-to-end
 * cases in `supabase-v3-builder.test.ts`, which exercise it through a builder
 * and so pin the wire envelope rather than the parse. These tests pin the parse
 * itself — in particular the escaping rules, which the naive predecessor
 * (`replace(/^%+/, '').replace(/%+$/, '')` plus `pattern.includes('_')`) got
 * wrong in both directions.
 *
 * Every pattern below is written as a JS string literal, so `\\` in the source
 * is a single backslash in the pattern the parser sees.
 */

type Case = {
  /** What the row pins, and the test's name. */
  name: string
  /** The SQL LIKE pattern, as a caller would pass it. */
  pattern: string
  expected: { needle: string; hasUnsupportedWildcard: boolean }
}

const CASES: Case[] = [
  {
    name: 'strips the unescaped leading and trailing %',
    pattern: '%abc%',
    expected: { needle: 'abc', hasUnsupportedWildcard: false },
  },
  {
    name: 'passes a wildcard-free pattern through untouched',
    pattern: 'abc',
    expected: { needle: 'abc', hasUnsupportedWildcard: false },
  },
  {
    name: 'reports an interior % as unsupported, keeping it in the needle',
    pattern: '%a%b%',
    expected: { needle: 'a%b', hasUnsupportedWildcard: true },
  },
  {
    name: 'reports an unescaped _ as unsupported',
    pattern: '%a_b%',
    expected: { needle: 'a_b', hasUnsupportedWildcard: true },
  },
  {
    name: 'treats an escaped % as a literal percent in the needle',
    // The 7-char pattern `%100\%%`: strippable wildcard, `100`, an escaped
    // literal `%`, strippable wildcard.
    pattern: '%100\\%%',
    expected: { needle: '100%', hasUnsupportedWildcard: false },
  },
  {
    name: 'treats an escaped _ as literal, without flagging it unsupported',
    pattern: '%under\\_score%',
    expected: { needle: 'under_score', hasUnsupportedWildcard: false },
  },
  {
    name: 'reduces an all-wildcard pattern to an empty needle',
    pattern: '%%',
    expected: { needle: '', hasUnsupportedWildcard: false },
  },
  {
    name: 'reduces an empty pattern to an empty needle',
    pattern: '',
    expected: { needle: '', hasUnsupportedWildcard: false },
  },
  {
    name: 'keeps an escaped backslash as a literal backslash',
    // `%a\\%` — the `\\` escapes a backslash, so the trailing `%` is still an
    // unescaped, strippable wildcard.
    pattern: '%a\\\\%',
    expected: { needle: 'a\\', hasUnsupportedWildcard: false },
  },
]

describe('parseLikeNeedle', () => {
  it.each(CASES)('$name', ({ pattern, expected }) => {
    expect(parseLikeNeedle(pattern)).toEqual(expected)
  })

  /**
   * Only LEADING and TRAILING `%` are strippable, and only UNESCAPED ones.
   *
   * Fuzzy matching is inherently unanchored, so a `%` at either end adds
   * nothing and can be dropped. An ESCAPED `\%` in the same position is not a
   * wildcard at all — it is a literal percent the user is searching for — so it
   * must stop the strip rather than be eaten by it. The old
   * `replace(/^%+/, '')` / `replace(/%+$/, '')` pair could not tell the two
   * apart and silently deleted the literal.
   */
  describe('strips only unescaped leading/trailing %', () => {
    it('stops stripping at an escaped % on either end', () => {
      expect(parseLikeNeedle('\\%abc\\%')).toEqual({
        needle: '%abc%',
        hasUnsupportedWildcard: false,
      })
    })

    it('keeps an escaped % that sits between two strippable ones', () => {
      // `%\%%` — the outer two are wildcards, the middle is the literal.
      expect(parseLikeNeedle('%\\%%')).toEqual({
        needle: '%',
        hasUnsupportedWildcard: false,
      })
    })

    it('does not strip an interior %, and reports it instead', () => {
      expect(parseLikeNeedle('a%b')).toEqual({
        needle: 'a%b',
        hasUnsupportedWildcard: true,
      })
    })
  })

  /**
   * A trailing lone backslash is kept as a literal backslash, deliberately.
   *
   * Postgres rejects such a pattern outright ("LIKE pattern must not end with
   * escape character"), so we could throw here too. We don't: this needle is
   * only ever an approximation feeding encrypted fuzzy matching, and the
   * plaintext `like` path never reaches this function, so refusing would turn a
   * database-level error into an earlier, less informative client-side one for
   * no gain. Treating the dangling escape as a literal keeps the needle
   * well-defined. This is pinned, not incidental — don't "fix" it into a throw.
   */
  it('keeps a trailing lone backslash as a literal backslash', () => {
    expect(parseLikeNeedle('abc\\')).toEqual({
      needle: 'abc\\',
      hasUnsupportedWildcard: false,
    })
  })

  // The interaction that actually decides whether a caller's query is accepted
  // or thrown out: `hasUnsupportedWildcard` must track UNESCAPED wildcards
  // only. The predecessor tested `pattern.includes('_')`, so every one of the
  // escaped cases below was rejected even though it is perfectly matchable.
  describe('hasUnsupportedWildcard tracks unescaped wildcards only', () => {
    it.each([
      ['\\_', 'a bare escaped underscore'],
      ['%under\\_score%', 'an escaped underscore between strippable wildcards'],
      ['a\\_b\\_c', 'several escaped underscores'],
      ['a\\%b', 'an escaped interior percent'],
    ])('stays false for %s (%s)', (pattern) => {
      expect(parseLikeNeedle(pattern).hasUnsupportedWildcard).toBe(false)
    })

    it.each([
      ['_abc', 'leading'],
      ['a_bc', 'interior'],
      ['abc_', 'trailing'],
      ['%a_c%', 'interior, inside strippable wildcards'],
      ['\\_a_b', 'interior, alongside an escaped underscore'],
    ])('goes true for an unescaped _ (%s: %s)', (pattern) => {
      expect(parseLikeNeedle(pattern).hasUnsupportedWildcard).toBe(true)
    })
  })
})
