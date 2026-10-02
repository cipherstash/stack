/**
 * v3 operator lowering — free-text search (`eqlMatch`).
 *
 * Canonical dialect: `eql_v3.matches(<col>, $n::eql_v3.query_<domain>)`.
 * The SQL function keeps its bundle name `contains`, but the semantics
 * are a bloom-filter TOKEN MATCH, not SQL LIKE/ILIKE and not
 * containment: the needle's downcased 3-gram set is tested as a subset
 * of the haystack's — order- and multiplicity-insensitive, and
 * one-sided (a `true` may be a false positive; a `false` never is).
 *
 * String needles are normalised and guarded BEFORE encryption
 * (`normalizeMatchNeedle` in `src/v3/operators-v3.ts`):
 *
 *   - leading/trailing `%` are STRIPPED (an `ilike`-shaped habit like
 *     `'%foo%'` still means "rows containing foo" under token
 *     matching) — the stripped needle is what gets encrypted;
 *   - an interior `%` or any `_` throws — the tokenizer would treat
 *     them as ordinary characters and silently match nothing;
 *   - a needle the column's match index cannot answer (empty after
 *     stripping, or below the tokenizer's token length) is rejected
 *     with the shared `matchNeedleError` reason (adapter-kit — same
 *     guard as the Drizzle and Supabase v3 surfaces).
 *
 * There is NO negated match (`eql_v3.matches` may false-positive, so
 * its negation would false-negative — silently dropping rows that
 * genuinely don't match; PR #655 review). The registry must not expose
 * one, pinned below.
 */

import { describe, expect, it } from 'vitest'
import { EncryptedString } from '../../src/execution/envelope-string'
import {
  cipherstashV3QueryOperations,
  EncryptionOperatorError,
  v3QueryTermTypeOf,
} from '../../src/v3/operators-v3'
import {
  callOperator,
  columnAccessorV3,
  contractV3,
  getOperator,
  literalParamValue,
  makeV3Adapter,
  selectWithWhere,
  TABLE,
  TEXT_SEARCH_CODEC_ID,
} from './operator-lowering-v3.helpers'

/** Lower `email.eqlMatch(needle)` and return the SQL + bound envelope. */
function lowerMatch(needle: unknown) {
  const predicate = callOperator(
    getOperator('eqlMatch'),
    columnAccessorV3(TABLE, 'email', TEXT_SEARCH_CODEC_ID),
    needle,
  )
  return makeV3Adapter().lower(selectWithWhere(predicate), {
    contract: contractV3,
  })
}

describe('cipherstash v3 operator lowering — eqlMatch', () => {
  it('lowers to eql_v3.matches(col, $1::eql_v3.query_text_search)', () => {
    const lowered = lowerMatch('alice')
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.matches("user"."email", $1::eql_v3.query_text_search)"`,
    )
  })

  it('binds the needle as an EncryptedString envelope with the freeTextSearch query-term mark', () => {
    const lowered = lowerMatch('alice')
    expect(lowered.params).toHaveLength(1)
    const envelope = literalParamValue(lowered.params[0])
    expect(envelope).toBeInstanceOf(EncryptedString)
    const handle = (envelope as EncryptedString).expose()
    expect(handle.plaintext).toBe('alice')
    expect(handle.table).toBe(TABLE)
    expect(handle.column).toBe('email')
    expect(v3QueryTermTypeOf(envelope as EncryptedString)).toBe(
      'freeTextSearch',
    )
  })
})

describe('cipherstash v3 operator lowering — eqlMatch needle guards', () => {
  it('strips leading/trailing % — the STRIPPED needle is what gets encrypted', () => {
    const lowered = lowerMatch('%alice%')
    expect(lowered.sql).toContain(
      'eql_v3.matches("user"."email", $1::eql_v3.query_text_search)',
    )
    expect(lowered.params).toHaveLength(1)
    const envelope = literalParamValue(lowered.params[0])
    expect(envelope).toBeInstanceOf(EncryptedString)
    // Not '%alice%': the SQL-wildcard shell is normalised away before
    // the needle reaches encryption.
    expect((envelope as EncryptedString).expose().plaintext).toBe('alice')
  })

  it('strips repeated and one-sided edge wildcards too', () => {
    expect(
      (
        literalParamValue(lowerMatch('%%alice').params[0]) as EncryptedString
      ).expose().plaintext,
    ).toBe('alice')
    expect(
      (
        literalParamValue(lowerMatch('alice%%%').params[0]) as EncryptedString
      ).expose().plaintext,
    ).toBe('alice')
  })

  it('rejects an interior % — the tokenizer cannot honor it', () => {
    expect(() => lowerMatch('ali%ce')).toThrow(EncryptionOperatorError)
    expect(() => lowerMatch('ali%ce')).toThrow(
      /has wildcards fuzzy free-text matching cannot honor/,
    )
  })

  it('rejects any _ wildcard, wherever it sits', () => {
    for (const needle of ['ali_ce', '_alice', 'alice_']) {
      expect(() => lowerMatch(needle), needle).toThrow(EncryptionOperatorError)
      expect(() => lowerMatch(needle), needle).toThrow(
        /has wildcards fuzzy free-text matching cannot honor/,
      )
    }
  })

  it('rejects a needle that is empty after stripping with the matchNeedleError reason', () => {
    expect(() => lowerMatch('%%')).toThrow(EncryptionOperatorError)
    expect(() => lowerMatch('%%')).toThrow(
      /^Operator "eqlMatch" cannot search column "email"/,
    )
    expect(() => lowerMatch('%%')).toThrow(/non-empty search term/)
  })

  it('rejects a needle below the match index token length with the matchNeedleError reason', () => {
    // The catalog's text_search match index tokenizes 3-grams; a
    // 2-codepoint needle blooms to nothing and would match EVERY row.
    expect(() => lowerMatch('ab')).toThrow(EncryptionOperatorError)
    expect(() => lowerMatch('ab')).toThrow(
      /^Operator "eqlMatch" cannot search column "email"/,
    )
    expect(() => lowerMatch('%ab%')).toThrow(/at least 3 characters/)
  })

  it('passes a pre-built envelope through ungated (non-string operands skip the needle guards)', () => {
    // Envelope operands fall through to coerceV3 — the guard only
    // normalises raw string needles.
    const userEnvelope = EncryptedString.from('%alice%')
    const lowered = lowerMatch(userEnvelope)
    expect(literalParamValue(lowered.params[0])).toBe(userEnvelope)
    expect(userEnvelope.expose().plaintext).toBe('%alice%')
  })
})

describe('cipherstash v3 registry — no negated match', () => {
  it('exposes neither eqlNotMatch nor the removed cipherstashNotIlike', () => {
    // `eql_v3.matches` is one-sided (may false-positive), so a negated
    // form would FALSE-NEGATIVE — silently dropping rows that genuinely
    // don't match. Until a decrypt-and-post-filter path exists, the
    // registry must not offer one (PR #655 review; same removal as the
    // Drizzle/Supabase v3 surfaces).
    const methods = Object.keys(cipherstashV3QueryOperations())
    expect(methods).not.toContain('eqlNotMatch')
    expect(methods).not.toContain('cipherstashNotIlike')
    expect(methods).toContain('eqlMatch')
  })
})
