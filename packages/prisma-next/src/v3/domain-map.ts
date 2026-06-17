// Ported from packages/drizzle/src/pg/v3/domain-map.ts.
//
// The (scalar, index) → eql_v3 domain SSOT. v3 is domain-based: each column is
// exactly one Postgres DOMAIN (`eql_v3.text_eq` / `text_match` / `text_ord`),
// chosen by its single index capability; the bare storage domain `eql_v3.text`
// is the base type the per-index domains narrow from.

// CastAs is the internal Protect cast-name. @cipherstash/schema is not a direct
// dependency and @cipherstash/stack does not re-export the CastAs *type* from
// its top-level entry, so we alias it locally to the only value this milestone
// uses. This mirrors derive-schemas.ts, which keeps its own local `DataType`.
// TODO(v3-scalars): replace with the real CastAs re-export when scalar #2 lands.
type CastAs = 'string'

/** v3 scalar names (column-facing API). NOT the same as CastAs. */
export type V3DataType = 'text'

/** v3 single-capability index choices for the text scalar. */
export type V3Index = 'equality' | 'freeTextSearch' | 'orderAndRange'

/** The closed set of v3 index values, as a runtime array (SSOT for {@link isV3Index}). */
export const V3_INDEX_VALUES = ['equality', 'freeTextSearch', 'orderAndRange'] as const

/** Narrow an `unknown` (e.g. a `typeParams.index` read from a contract) to {@link V3Index}. */
export function isV3Index(value: unknown): value is V3Index {
  return typeof value === 'string' && (V3_INDEX_VALUES as readonly string[]).includes(value)
}

/**
 * Per-scalar capability table. Keyed by scalar so adding int/date/timestamptz is
 * a type-shape extension (new key + its valid index subset), not a row append
 * that lets invalid (scalar, capability) tuples type-check.
 */
const DOMAINS: Record<V3DataType, { storage: string; byIndex: Record<V3Index, string> }> = {
  text: {
    storage: 'eql_v3.text',
    byIndex: { equality: 'eql_v3.text_eq', freeTextSearch: 'eql_v3.text_match', orderAndRange: 'eql_v3.text_ord' },
  },
}

/**
 * Single source of truth for the v3 domain sql-names, derived from DOMAINS by
 * flattening storage + per-index values, so the domain set has exactly one
 * definition (no "keep in sync" hazard).
 */
export const ALL_V3_DOMAINS: ReadonlySet<string> = new Set(
  Object.values(DOMAINS).flatMap((scalar) => [scalar.storage, ...Object.values(scalar.byIndex)]),
)

const CAST_AS: Record<V3DataType, CastAs> = { text: 'string' }

export function eqlV3Domain(dataType: V3DataType, index: V3Index | undefined): string {
  const scalar = DOMAINS[dataType]
  if (!scalar) throw new Error(`Unsupported v3 dataType "${dataType}". Only "text" is supported in this milestone.`)
  if (index === undefined) return scalar.storage
  const domain = scalar.byIndex[index]
  if (!domain) throw new Error(`Unsupported v3 index "${index}" for dataType "${dataType}".`)
  return domain
}

export function v3CastAs(dataType: V3DataType): CastAs {
  const castAs = CAST_AS[dataType]
  if (!castAs) throw new Error(`Unsupported v3 dataType "${dataType}".`)
  return castAs
}
