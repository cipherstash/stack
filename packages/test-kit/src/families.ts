import {
  type DomainSpec,
  deferredReason,
  type EqlV3TypeName,
  eqlTypeSlug,
  isCovered,
  typedEntries,
  V3_MATRIX,
} from './catalog.ts'

/**
 * Integration suites are split one file per plaintext family, not one per
 * domain (39 files per adapter) nor one per capability tier (which buries the
 * plaintext axis that actually drives the samples and the oracle). A family is
 * the set of domains sharing a plaintext type and sample set — `integer`,
 * `integer_eq`, `integer_ord`, `integer_ord_ore` — so one file seeds one table
 * and exercises every capability tier that plaintext supports.
 */
export type FamilyName =
  | 'integer'
  | 'smallint'
  | 'bigint'
  | 'real-double'
  | 'numeric'
  | 'date'
  | 'timestamp'
  | 'text'
  | 'boolean'
  | 'json'

/**
 * The bare-domain prefixes each family owns. `real-double` pairs two prefixes
 * because both are IEEE floats over the same sample set; every other family is
 * one prefix.
 *
 * Matched against the BARE domain (`integer_ord`), not the slug: `eqlTypeSlug`
 * strips only the `public.` schema, so a slug is `eql_v3_integer_ord`. The slug
 * stays the physical column name, matching the existing matrix suites.
 */
const FAMILY_PREFIXES: Readonly<Record<FamilyName, readonly string[]>> = {
  integer: ['integer'],
  smallint: ['smallint'],
  bigint: ['bigint'],
  'real-double': ['real', 'double'],
  numeric: ['numeric'],
  date: ['date'],
  timestamp: ['timestamp'],
  text: ['text'],
  boolean: ['boolean'],
  // `json` is here only for coverage accounting — its one domain (`eql_v3_json_search`)
  // is marked `deferred`, meaning "not run by the scalar op-matrix", because JSON
  // is queried by containment (`@>`), not the eq/ord/match ops the oracle models.
  // It is NOT unimplemented: dedicated live suites (`json-crypto` and the shared adapter JSON suite)
  // cover it. (Contrast the ORE domains, also `deferred` but because their opclass
  // is superuser-only and cannot run on managed Postgres.)
  json: ['json'],
}

export const FAMILY_NAMES = Object.keys(FAMILY_PREFIXES) as FamilyName[]

/** One family column: its physical column name, its domain, and its catalog row. */
export type FamilyDomain = Readonly<{
  /** Physical column name in the test table, e.g. `eql_v3_integer_ord`. */
  slug: string
  /** The domain without its `eql_v3_` prefix, e.g. `integer_ord`. Drives family matching. */
  bare: string
  eqlType: EqlV3TypeName
  spec: DomainSpec
}>

/** `public.eql_v3_integer_ord` → `integer_ord`. */
function bareDomain(eqlType: EqlV3TypeName | string): string {
  return eqlTypeSlug(eqlType).replace(/^eql_v3_/, '')
}

/**
 * `integer` must not swallow `smallint`, and `date` must not swallow
 * `timestamp` — but `text` legitimately owns `text_search`. Match on the prefix
 * followed by end-of-string or `_`, so `date` claims `date` and `date_ord`
 * while `timestamp*` stays with `timestamp`. A naive `startsWith` would not.
 */
function belongsTo(bare: string, prefix: string): boolean {
  return bare === prefix || bare.startsWith(`${prefix}_`)
}

function rowsMatching(
  family: FamilyName,
  covered: boolean,
): Array<[EqlV3TypeName, DomainSpec]> {
  const prefixes = FAMILY_PREFIXES[family]
  return typedEntries(V3_MATRIX)
    .filter(([, spec]) => isCovered(spec) === covered)
    .filter(([eqlType]) =>
      prefixes.some((p) => belongsTo(bareDomain(eqlType), p)),
    )
}

/**
 * Every domain in a family that the integration matrix covers, in catalog order.
 * Deferred domains (see {@link DomainSpec.deferred}) are excluded here rather
 * than skipped per-test, so a family file cannot accidentally assert against a
 * domain the database does not have.
 */
export function domainsForFamily(family: FamilyName): FamilyDomain[] {
  return rowsMatching(family, true).map(([eqlType, spec]) => ({
    slug: eqlTypeSlug(eqlType),
    bare: bareDomain(eqlType),
    eqlType,
    spec,
  }))
}

/** Domains a family declares but the matrix skips, with the reason. Reported by the driver. */
export function deferredForFamily(
  family: FamilyName,
): Array<{ slug: string; bare: string; reason: string }> {
  return rowsMatching(family, false).map(([eqlType, spec]) => ({
    slug: eqlTypeSlug(eqlType),
    bare: bareDomain(eqlType),
    reason: deferredReason(spec) ?? '',
  }))
}
