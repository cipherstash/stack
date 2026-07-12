import type { DomainSpec } from './catalog.ts'
import type { Plain } from './ops.ts'

/**
 * The expected result of every query is computed from the PLAINTEXT, never
 * restated as a literal. Lifted from `drizzle-v3/operators-live-pg.test.ts`,
 * which is where these rules were originally worked out; the comments are the
 * load-bearing part.
 */

/**
 * Row `i` of a domain takes `samples[min(i, len - 1)]`. Domains with fewer
 * distinct samples than there are rows therefore REUSE their last value, which
 * is deliberate: it produces ties, so ordering tie-breaks and range boundaries
 * are exercised rather than vacuously satisfied.
 */
export function plainValue(
  spec: DomainSpec,
  rowKeys: readonly string[],
  rowKey: string,
): Plain {
  const index = rowKeys.indexOf(rowKey)
  if (index < 0) throw new Error(`Unknown row key: ${rowKey}`)
  const sample = spec.samples[Math.min(index, spec.samples.length - 1)]
  if (sample === undefined) {
    throw new Error(`Domain has no samples for row ${rowKey}`)
  }
  // Samples widened to include `JsonValue` for the (deferred) json domain; the
  // scalar oracle is only ever called on covered scalar domains, so this narrows
  // safely.
  return sample as Plain
}

export function comparePlain(left: Plain, right: Plain): number {
  if (left instanceof Date && right instanceof Date) {
    return left.getTime() - right.getTime()
  }
  if (typeof left === 'number' && typeof right === 'number') {
    return left - right
  }
  // bigint order domains (`bigint_ord`/`bigint_ord_ore`) carry i64 samples
  // beyond Number.MAX_SAFE_INTEGER, so they must be compared as bigints — the
  // subtraction is narrowed to -1/0/1 because callers expect a `number`.
  if (typeof left === 'bigint' && typeof right === 'bigint') {
    return left < right ? -1 : left > right ? 1 : 0
  }
  if (typeof left === 'string' && typeof right === 'string') {
    // eql_v3 text ordering is BYTEWISE, not locale-collated: the oracle must
    // model codepoint order, not `localeCompare` (which folds case, reorders
    // punctuation vs letters, and is locale-dependent). Text samples must stay
    // ASCII/unambiguous so UTF-16 code-unit order == the byte order the DB
    // actually sorts by.
    return left < right ? -1 : left > right ? 1 : 0
  }
  if (typeof left === 'boolean' && typeof right === 'boolean') {
    return Number(left) - Number(right)
  }
  throw new Error(
    `Unsupported ordered values: ${String(left)}, ${String(right)}`,
  )
}

/** Row keys whose plaintext satisfies `predicate`. The NULL row is never included. */
export function expectedKeysFor(
  spec: DomainSpec,
  rowKeys: readonly string[],
  predicate: (value: Plain) => boolean,
): string[] {
  return rowKeys.filter((rowKey) =>
    predicate(plainValue(spec, rowKeys, rowKey)),
  )
}

/**
 * Oracle for the encrypted ORDER BY. Domains with fewer samples than rows give
 * two rows equal values, so the comparison alone does not determine the row
 * order — ties break on `rowKey` ascending, which the query mirrors with a
 * secondary `ORDER BY row_key`. Without that both sides would be arbitrary and
 * the test would flake rather than prove ordering.
 */
export function sortedKeysFor(
  spec: DomainSpec,
  rowKeys: readonly string[],
  direction: 'asc' | 'desc',
): string[] {
  return [...rowKeys].sort((left, right) => {
    const cmp = comparePlain(
      plainValue(spec, rowKeys, left),
      plainValue(spec, rowKeys, right),
    )
    if (cmp !== 0) return direction === 'asc' ? cmp : -cmp
    return left < right ? -1 : left > right ? 1 : 0
  })
}

/**
 * The `contains` oracle. The match index downcases and tokenizes into 3-grams
 * with `include_original: true`, so a needle matches iff it appears in the
 * downcased value — with the caveat that a needle longer than the tokenizer
 * window contributes a whole-value token no stored trigram supplies. Family
 * files choose needles accordingly; this models the plaintext side only.
 */
export function containsPlain(value: Plain, needle: string): boolean {
  return String(value).toLowerCase().includes(needle.toLowerCase())
}
