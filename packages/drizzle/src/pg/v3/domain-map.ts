import type { CastAs } from '@cipherstash/schema'

/** v3 scalar names (column-facing API). NOT the same as CastAs. */
export type V3DataType = 'text'

/** v3 single-capability index choices for the text scalar. */
export type V3Index = 'equality' | 'freeTextSearch' | 'orderAndRange'

/**
 * Per-scalar capability table. Keyed by scalar so adding int/date/timestamptz
 * is a type-shape extension (new key + its valid index subset), not a row append
 * that lets invalid (scalar, capability) tuples type-check (spec §5.1, §11 item 5).
 */
const DOMAINS: Record<
  V3DataType,
  { storage: string; byIndex: Record<V3Index, string> }
> = {
  text: {
    storage: 'eql_v3.text',
    byIndex: {
      equality: 'eql_v3.text_eq',
      freeTextSearch: 'eql_v3.text_match',
      orderAndRange: 'eql_v3.text_ord',
    },
  },
}

/**
 * Single source of truth for the v3 domain sql-names, derived from DOMAINS by
 * flattening the storage + per-index values. The encrypted-column detection
 * predicate in index.ts imports this instead of re-listing the strings, so the
 * domain set has exactly one definition (no "keep in sync" hazard).
 */
export const ALL_V3_DOMAINS: ReadonlySet<string> = new Set(
  Object.values(DOMAINS).flatMap((scalar) => [
    scalar.storage,
    ...Object.values(scalar.byIndex),
  ]),
)

/** Translate a v3 scalar name to the internal Protect CastAs (spec §5.1). */
const CAST_AS: Record<V3DataType, CastAs> = {
  text: 'string',
}

export function eqlV3Domain(
  dataType: V3DataType,
  index: V3Index | undefined,
): string {
  const scalar = DOMAINS[dataType]
  if (!scalar) {
    throw new Error(
      `Unsupported v3 dataType "${dataType}". Only "text" is supported in this milestone.`,
    )
  }
  if (index === undefined) {
    return scalar.storage
  }
  const domain = scalar.byIndex[index]
  if (!domain) {
    throw new Error(
      `Unsupported v3 index "${index}" for dataType "${dataType}".`,
    )
  }
  return domain
}

export function v3CastAs(dataType: V3DataType): CastAs {
  const castAs = CAST_AS[dataType]
  if (!castAs) {
    throw new Error(`Unsupported v3 dataType "${dataType}".`)
  }
  return castAs
}
