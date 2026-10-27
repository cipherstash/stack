/**
 * The plaintext Postgres type an EQL v3 domain decrypts back to — the inverse
 * of the forward mapping, where a plaintext column of some type is given an
 * `eql_v3_<family>[_<suffix>]` domain twin.
 *
 * Keyed by the domain FAMILY, not the full domain name: every domain in a
 * family (`eql_v3_text`, `_eq`, `_match`, `_ord`, `_ord_ore`, `_ord_ope`,
 * `_search`, `_search_ore`) encrypts the same plaintext kind and differs only
 * in which query terms it carries. The suffixes are dropped on the way back
 * because a plaintext column needs no terms — ordinary Postgres operators and
 * indexes answer every query the encrypted terms did.
 *
 * The families mirror `packages/eql/crates/eql-domains` (the catalog every EQL
 * v3 domain is generated from). Two choices are deliberate:
 *
 * - `timestamp` → `timestamptz`. EQL's `timestamp` family encrypts an INSTANT
 *   (UTC-normalised); its catalog entry says so explicitly. A naive
 *   `timestamp` column would silently reinterpret those instants in the
 *   session time zone.
 * - `json` → `jsonb`. Both the searchable document (`eql_v3_json_search`) and
 *   the storage-only `eql_v3_json` decrypt to a JSON value; `jsonb` is the type
 *   the forward path accepts for JSON and the one EQL's searchable JSON models.
 *   The `json_entry` / `json_query` domains are SteVec fragments and query
 *   needles, never a column's type, so they deliberately have no mapping.
 */
const FAMILY_PLAINTEXT_TYPES = {
  text: 'text',
  integer: 'integer',
  smallint: 'smallint',
  bigint: 'bigint',
  numeric: 'numeric',
  real: 'real',
  double: 'double precision',
  boolean: 'boolean',
  date: 'date',
  timestamp: 'timestamptz',
  json: 'jsonb',
} as const

/** An EQL v3 domain family this module can map back to plaintext. */
export type EqlDomainFamily = keyof typeof FAMILY_PLAINTEXT_TYPES

/** The plaintext Postgres type for an {@link EqlDomainFamily}. */
export type PlaintextSqlType = (typeof FAMILY_PLAINTEXT_TYPES)[EqlDomainFamily]

/**
 * Suffixes each family's scalar domains may carry, per the EQL catalog. A
 * domain name is accepted only as `eql_v3_<family>` or
 * `eql_v3_<family>_<suffix>` with a suffix listed here, so a future domain
 * this release does not know about is refused rather than guessed at.
 */
const ORDERED_SUFFIXES = ['eq', 'ord', 'ord_ore', 'ord_ope'] as const
const FAMILY_SUFFIXES: Record<EqlDomainFamily, readonly string[]> = {
  text: [...ORDERED_SUFFIXES, 'match', 'search', 'search_ore'],
  integer: ORDERED_SUFFIXES,
  smallint: ORDERED_SUFFIXES,
  bigint: ORDERED_SUFFIXES,
  numeric: ORDERED_SUFFIXES,
  real: ORDERED_SUFFIXES,
  double: ORDERED_SUFFIXES,
  date: ORDERED_SUFFIXES,
  timestamp: ORDERED_SUFFIXES,
  boolean: [],
  json: ['search'],
}

/** A domain resolved to its family and plaintext type. */
export interface PlaintextTypeMapping {
  /** The unqualified domain, e.g. `eql_v3_text_search`. */
  domain: string
  family: EqlDomainFamily
  /** The Postgres type to give the plaintext twin, e.g. `text`. */
  sqlType: PlaintextSqlType
}

/**
 * Map an EQL v3 domain name to the plaintext Postgres type its values decrypt
 * to. Accepts the bare (`eql_v3_text_search`) or `public.`-qualified form.
 * Returns `null` for anything that is not a known EQL v3 column domain — a
 * legacy `eql_v2_encrypted`, a SteVec fragment, or a domain newer than this
 * release — so callers refuse instead of inventing a type.
 */
export function plaintextTypeForEqlDomain(
  domainName: string,
): PlaintextTypeMapping | null {
  const domain = domainName.startsWith('public.')
    ? domainName.slice('public.'.length)
    : domainName
  if (!domain.startsWith('eql_v3_')) return null
  const rest = domain.slice('eql_v3_'.length)

  // Longest family first, so a hypothetical family that prefixes another can
  // never be shadowed by the shorter one.
  const families = (
    Object.keys(FAMILY_PLAINTEXT_TYPES) as EqlDomainFamily[]
  ).sort((a, b) => b.length - a.length)
  for (const family of families) {
    if (rest === family) {
      return { domain, family, sqlType: FAMILY_PLAINTEXT_TYPES[family] }
    }
    if (rest.startsWith(`${family}_`)) {
      const suffix = rest.slice(family.length + 1)
      if (FAMILY_SUFFIXES[family].includes(suffix)) {
        return { domain, family, sqlType: FAMILY_PLAINTEXT_TYPES[family] }
      }
      return null
    }
  }
  return null
}
