import { describe, expect, it } from 'vitest'
import {
  inferIndexType,
  resolveIndexType,
} from '@/encryption/helpers/infer-index-type'
import { articles, metadata, products, users } from './fixtures'

/**
 * The credentialed `encrypt-query` suite asserts live EQL term keys (`hm`, `bf`,
 * `op`, `ob`) and preflight error messages that are decided entirely by which
 * index `inferIndexType`/`resolveIndexType` picks for each shared fixture
 * column. Nothing else pins that mapping down, so swapping a fixture's v3 domain
 * silently re-points those tests at a different index — they then pass for the
 * wrong reason, or fail with a message that reads like an unrelated product
 * regression.
 *
 * #829 shipped exactly that: `articles.content` moved from a match-only column
 * to `types.TextSearch`, whose `unique + ope + match` derivation outranks `match`
 * in `inferIndexType`'s priority order. The numeric-value guard in
 * `validateValueIndexCompatibility` (which only fires for `match`) stopped
 * firing, and "fails when encrypting number with auto-inferred match index"
 * surfaced a protect-ffi cast error instead of the guard's message.
 *
 * These assertions are credential-free, so a fixture that drifts fails on the
 * PR that drifts it rather than on the first CI run holding live credentials.
 */
describe('shared query fixtures resolve to the indexes the live suite assumes', () => {
  describe('auto-inference (no explicit queryType)', () => {
    it.each([
      { name: 'users.email', column: () => users.email, expected: 'unique' },
      { name: 'users.age', column: () => users.age, expected: 'ope' },
      {
        name: 'articles.content',
        column: () => articles.content,
        expected: 'match',
      },
      { name: 'products.price', column: () => products.price, expected: 'ore' },
    ])('$name infers $expected', ({ column, expected }) => {
      expect(inferIndexType(column())).toBe(expected)
    })

    it('metadata.raw carries no queryable index at all', () => {
      expect(() => inferIndexType(metadata.raw)).toThrow(
        /no indexes configured/,
      )
    })
  })

  describe('explicit queryType', () => {
    it('users.bio answers freeTextSearch through the match index', () => {
      expect(resolveIndexType(users.bio, 'freeTextSearch').indexType).toBe(
        'match',
      )
    })

    it('users.age answers equality through its ordering index, not hm', () => {
      // A numeric `_ord` domain carries no `unique`/`hm`; equality resolves to
      // the same OPE term `orderAndRange` emits, distinguished by the SQL `=`.
      expect(resolveIndexType(users.age, 'equality').indexType).toBe('ope')
    })

    it('articles.content cannot answer equality', () => {
      // Keeps a genuinely equality-incapable fixture available for the live
      // suite's queryType-mismatch assertion.
      expect(() => resolveIndexType(articles.content, 'equality')).toThrow(
        /Index type "unique" is not configured/,
      )
    })
  })
})
