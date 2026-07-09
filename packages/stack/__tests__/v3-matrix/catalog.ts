/**
 * Type-driven v3 test matrix — single source of truth.
 *
 * The TypeScript analog of the Rust `eql_v3` `scalar_matrix!` harness
 * (`encrypt-query-language/tests/sqlx`): one declarative catalog drives both a
 * runtime `it.each` matrix (`matrix.test.ts`) and type-level assertions
 * (`matrix.test-d.ts`), instead of hand-rolling per-domain test bodies.
 *
 * COVERAGE IS MANDATORY. The catalog is `satisfies Record<EqlV3TypeName,
 * DomainSpec>`, and `EqlV3TypeName` is derived from the real column union
 * (`AnyEncryptedV3Column`). Add a domain to the SDK and this file fails to
 * compile until it has a row — the compile-time analog of, and stronger than,
 * the Rust `test:matrix:inventory` cross-check (it names each missing domain).
 *
 * Every field here is consumed by a test: `builder`/`ColumnClass` by the
 * instanceof check, `castAs` + `indexes` by the `build()` `toStrictEqual`, and
 * `capabilities` by `getQueryCapabilities()`/`isQueryable()`.
 */

import type {
  AnyEncryptedV3Column,
  EqlTypeForColumn,
  QueryCapabilities,
} from '@/eql/v3'
import {
  EncryptedBigintColumn,
  EncryptedBigintEqColumn,
  EncryptedBigintOrdColumn,
  EncryptedBigintOrdOreColumn,
  EncryptedBooleanColumn,
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn,
  EncryptedDateOrdOreColumn,
  EncryptedDoubleColumn,
  EncryptedDoubleEqColumn,
  EncryptedDoubleOrdColumn,
  EncryptedDoubleOrdOreColumn,
  EncryptedIntegerColumn,
  EncryptedIntegerEqColumn,
  EncryptedIntegerOrdColumn,
  EncryptedIntegerOrdOreColumn,
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn,
  EncryptedNumericOrdOreColumn,
  EncryptedRealColumn,
  EncryptedRealEqColumn,
  EncryptedRealOrdColumn,
  EncryptedRealOrdOreColumn,
  EncryptedSmallintColumn,
  EncryptedSmallintEqColumn,
  EncryptedSmallintOrdColumn,
  EncryptedSmallintOrdOreColumn,
  EncryptedTextColumn,
  EncryptedTextEqColumn,
  EncryptedTextMatchColumn,
  EncryptedTextOrdColumn,
  EncryptedTextOrdOreColumn,
  EncryptedTextSearchColumn,
  EncryptedTimestampColumn,
  EncryptedTimestampEqColumn,
  EncryptedTimestampOrdColumn,
  EncryptedTimestampOrdOreColumn,
  types,
} from '@/eql/v3'
import type { ColumnSchema } from '@/schema'

/**
 * The canonical union of every v3 domain name — derived STRAIGHT from the real
 * column union (`AnyEncryptedV3Column`) via the exported `EqlTypeForColumn`
 * helper, not hand-copied. This is the key set the `Record` below must cover.
 */
export type EqlV3TypeName = EqlTypeForColumn<AnyEncryptedV3Column>

/** One row of the type-driven matrix: everything a test needs about a domain. */
export type DomainSpec = Readonly<{
  /** Column builder under test. */
  builder: (name: string) => AnyEncryptedV3Column
  /** Concrete class the builder must instantiate (`toBeInstanceOf`). */
  ColumnClass: new (
    ...args: never[]
  ) => AnyEncryptedV3Column
  /** Plaintext axis emitted by `build().cast_as`. */
  castAs: ColumnSchema['cast_as']
  /** Semantic capability flags (`getQueryCapabilities()`). */
  capabilities: QueryCapabilities
  /**
   * The full `build().indexes` output — stored as DATA per row (like the Rust
   * harness) rather than derived from `capabilities`, because `text_search`
   * overrides `build()` to emit `unique + ore + match` where the capability →
   * index rule would omit `unique` for an order-capable column.
   */
  indexes: ColumnSchema['indexes']
  /**
   * Representative + edge plaintext values that MUST round-trip through live
   * encrypt/decrypt (consumed by `matrix-live.test.ts`). Typed as the loose
   * plaintext union rather than per-row: the precise `castAs → plaintext` axis
   * is already proven at the type level in `matrix.test-d.ts` (`InferPlaintext`),
   * and a per-row generic would break the single `satisfies Record<…>` that is
   * this file's coverage mechanism. Numeric samples are split integer-vs-
   * fractional: `build()` emits `cast_as:'number'` uniformly so the FFI can't
   * tell `integer` from `double`, and a fractional value on an int-named domain is
   * untested territory (it would truncate against a real narrow PG column).
   */
  samples: ReadonlyArray<string | number | bigint | boolean | Date>
  /**
   * Values that MUST fail encryption. Number domains reject `NaN`/`±Infinity`
   * and `bigint` domains reject values outside the signed 64-bit (`int8`) range
   * — both via the same client-side guard (`assertValidNumericValue`). Domains
   * whose plaintext type cannot express an invalid value omit this.
   */
  errorSamples?: ReadonlyArray<number | bigint>
}>

/**
 * `Object.entries` that preserves the literal key union instead of widening to
 * `string` — so `eqlType` in the runtime matrix stays `EqlV3TypeName`.
 */
export function typedEntries<K extends string, V>(
  obj: Record<K, V>,
): Array<[K, V]> {
  return Object.entries(obj) as Array<[K, V]>
}

/** The schema the concrete EQL v3 domains live in — see `EqlV3TypeName`. */
export const EQL_V3_DOMAIN_SCHEMA = 'public'

/**
 * A `public.eql_v3_integer_ord` domain reduced to a bare `integer_ord`, suitable as a
 * column identifier in the test tables. Shared by every suite that builds a
 * table from the matrix, so a future domain-schema move is a one-line change
 * rather than five.
 */
export function eqlTypeSlug(eqlType: EqlV3TypeName | string): string {
  const prefix = `${EQL_V3_DOMAIN_SCHEMA}.`
  return eqlType.startsWith(prefix) ? eqlType.slice(prefix.length) : eqlType
}

// Capability shorthands (mirror the SDK's internal presets).
const STORAGE = {
  equality: false,
  orderAndRange: false,
  freeTextSearch: false,
} as const
const EQ = {
  equality: true,
  orderAndRange: false,
  freeTextSearch: false,
} as const
const ORD = {
  equality: true,
  orderAndRange: true,
  freeTextSearch: false,
} as const
const MATCH_ONLY = {
  equality: false,
  orderAndRange: false,
  freeTextSearch: true,
} as const
const FULL = {
  equality: true,
  orderAndRange: true,
  freeTextSearch: true,
} as const

// Index shorthands (mirror `build().indexes`). Type-annotated rather than
// `as const`: annotation contextually types the literals so enum fields like
// `kind: 'ngram'` stay checked against the schema while arrays remain MUTABLE
// — `ColumnSchema['indexes']` rejects the `readonly` arrays `as const` produces.
type Indexes = ColumnSchema['indexes']
const NONE: Indexes = {}
const UNIQUE_IDX: Indexes = { unique: { token_filters: [] } }
// Ordering flavour is pinned by the domain name (eql-3.0.0): `_ord_ore`
// domains are block-ORE (`ore` index, `ob` term); plain `_ord` domains and
// `text_search` are CLLW-OPE (`ope` index, `op` term).
const ORE_IDX: Indexes = { ore: {} }
const OPE_IDX: Indexes = { ope: {} }
// Text order domains (`text_ord`, `text_ord_ore`) carry BOTH `hm` (unique) and
// their ordering term: their eql_v3 SQL domains require `hm` because text
// equality is HMAC-based, unlike numeric/date order domains which answer
// equality via the ordering term.
const TEXT_ORD_IDX: Indexes = { unique: { token_filters: [] }, ope: {} }
const TEXT_ORD_ORE_IDX: Indexes = { unique: { token_filters: [] }, ore: {} }
const MATCH_BLOCK: NonNullable<Indexes>['match'] = {
  tokenizer: { kind: 'ngram', token_length: 3 },
  token_filters: [{ kind: 'downcase' }],
  k: 6,
  m: 2048,
  include_original: true,
}
const MATCH_IDX: Indexes = { match: MATCH_BLOCK }
const TEXT_SEARCH_IDX: Indexes = {
  unique: { token_filters: [] },
  ope: {},
  match: MATCH_BLOCK,
}

// Sample plaintexts per plaintext axis, consumed by `matrix-live.test.ts`.
// Numeric sets are split by domain width: integers (incl. type bounds) for
// smallint/integer, fractionals for real/double/numeric. See `DomainSpec.samples`.
const SMALLINT_S = [0, -1, 32767, -32768] as const
const INTEGER_S = [0, -42, 2147483647, -2147483648] as const
// Full i64 bounds: i64::MAX, i64::MIN, zero, a negative, and a mid value beyond
// Number.MAX_SAFE_INTEGER to prove protect-ffi 0.28 round-trips a JS bigint
// losslessly. Values OUTSIDE this range are rejected client-side (BIGINT_ERR)
// before protect-ffi, mirroring how NUM_ERR guards the number domains.
const BIGINT_S = [
  4611686018427387904n,
  -42n,
  9223372036854775807n,
  -9223372036854775808n,
  0n,
] as const
const REAL_S = [0, 77.5, -117.25, 0.5] as const
const DOUBLE_S = [0, -117.123456, 1e15, -1e15] as const
const NUMERIC_S = [0, 12345.678, -42, -0.5] as const
const TEXT_S = ['', 'ada@example.com', 'Ada Lovelace'] as const
// Text domains with an ordering term require non-empty positive samples to
// satisfy the real Postgres domain checks. Empty-string rejection is covered in
// matrix-live-pg.
const TEXT_ORE_S = [
  'ada@example.com',
  'grace@example.com',
  'zora@example.org',
] as const
const BOOLEAN_S = [true, false] as const
const DATE_S = [
  new Date('2026-07-01T00:00:00.000Z'),
  new Date('1970-01-01T00:00:00.000Z'),
] as const
// Timestamp domains (`cast_as: 'timestamp'`) preserve the full instant, unlike
// `date` which truncates to midnight. These samples deliberately carry a
// NON-ZERO time-of-day so the live round-trip actually detects a regression
// that truncates to the day boundary — reusing the midnight-only `DATE_S` here
// would let such a regression pass silently (see matrix.test.ts).
const TS_S = [
  new Date('2026-07-01T12:34:56.000Z'),
  new Date('1970-01-01T23:59:59.000Z'),
] as const
// Every number domain rejects these via the global encrypt guard.
const NUM_ERR = [
  Number.NaN,
  Number.POSITIVE_INFINITY,
  Number.NEGATIVE_INFINITY,
] as const
// Every bigint domain rejects values outside the signed 64-bit (`int8`) range
// via the same guard — the bigint analog of NUM_ERR's NaN/±Infinity: i64::MAX+1
// and i64::MIN-1.
const BIGINT_ERR = [9223372036854775808n, -9223372036854775809n] as const

// biome-ignore format: one row per domain reads as a table; keep it dense.
export const V3_MATRIX = {
  // integer
  'public.eql_v3_integer': { builder: types.Integer, ColumnClass: EncryptedIntegerColumn, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: INTEGER_S, errorSamples: NUM_ERR },
  'public.eql_v3_integer_eq': { builder: types.IntegerEq, ColumnClass: EncryptedIntegerEqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: INTEGER_S, errorSamples: NUM_ERR },
  'public.eql_v3_integer_ord_ore': { builder: types.IntegerOrdOre, ColumnClass: EncryptedIntegerOrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: INTEGER_S, errorSamples: NUM_ERR },
  'public.eql_v3_integer_ord': { builder: types.IntegerOrd, ColumnClass: EncryptedIntegerOrdColumn, castAs: 'number', capabilities: ORD, indexes: OPE_IDX, samples: INTEGER_S, errorSamples: NUM_ERR },
  // smallint
  'public.eql_v3_smallint': { builder: types.Smallint, ColumnClass: EncryptedSmallintColumn, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: SMALLINT_S, errorSamples: NUM_ERR },
  'public.eql_v3_smallint_eq': { builder: types.SmallintEq, ColumnClass: EncryptedSmallintEqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: SMALLINT_S, errorSamples: NUM_ERR },
  'public.eql_v3_smallint_ord_ore': { builder: types.SmallintOrdOre, ColumnClass: EncryptedSmallintOrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: SMALLINT_S, errorSamples: NUM_ERR },
  'public.eql_v3_smallint_ord': { builder: types.SmallintOrd, ColumnClass: EncryptedSmallintOrdColumn, castAs: 'number', capabilities: ORD, indexes: OPE_IDX, samples: SMALLINT_S, errorSamples: NUM_ERR },
  // bigint (int8) — native JS bigint round-trip on protect-ffi 0.28; ungated
  'public.eql_v3_bigint': { builder: types.Bigint, ColumnClass: EncryptedBigintColumn, castAs: 'bigint', capabilities: STORAGE, indexes: NONE, samples: BIGINT_S, errorSamples: BIGINT_ERR },
  'public.eql_v3_bigint_eq': { builder: types.BigintEq, ColumnClass: EncryptedBigintEqColumn, castAs: 'bigint', capabilities: EQ, indexes: UNIQUE_IDX, samples: BIGINT_S, errorSamples: BIGINT_ERR },
  'public.eql_v3_bigint_ord_ore': { builder: types.BigintOrdOre, ColumnClass: EncryptedBigintOrdOreColumn, castAs: 'bigint', capabilities: ORD, indexes: ORE_IDX, samples: BIGINT_S, errorSamples: BIGINT_ERR },
  'public.eql_v3_bigint_ord': { builder: types.BigintOrd, ColumnClass: EncryptedBigintOrdColumn, castAs: 'bigint', capabilities: ORD, indexes: OPE_IDX, samples: BIGINT_S, errorSamples: BIGINT_ERR },
  // date
  'public.eql_v3_date': { builder: types.Date, ColumnClass: EncryptedDateColumn, castAs: 'date', capabilities: STORAGE, indexes: NONE, samples: DATE_S },
  'public.eql_v3_date_eq': { builder: types.DateEq, ColumnClass: EncryptedDateEqColumn, castAs: 'date', capabilities: EQ, indexes: UNIQUE_IDX, samples: DATE_S },
  'public.eql_v3_date_ord_ore': { builder: types.DateOrdOre, ColumnClass: EncryptedDateOrdOreColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX, samples: DATE_S },
  'public.eql_v3_date_ord': { builder: types.DateOrd, ColumnClass: EncryptedDateOrdColumn, castAs: 'date', capabilities: ORD, indexes: OPE_IDX, samples: DATE_S },
  // timestamp
  'public.eql_v3_timestamp': { builder: types.Timestamp, ColumnClass: EncryptedTimestampColumn, castAs: 'timestamp', capabilities: STORAGE, indexes: NONE, samples: TS_S },
  'public.eql_v3_timestamp_eq': { builder: types.TimestampEq, ColumnClass: EncryptedTimestampEqColumn, castAs: 'timestamp', capabilities: EQ, indexes: UNIQUE_IDX, samples: TS_S },
  'public.eql_v3_timestamp_ord_ore': { builder: types.TimestampOrdOre, ColumnClass: EncryptedTimestampOrdOreColumn, castAs: 'timestamp', capabilities: ORD, indexes: ORE_IDX, samples: TS_S },
  'public.eql_v3_timestamp_ord': { builder: types.TimestampOrd, ColumnClass: EncryptedTimestampOrdColumn, castAs: 'timestamp', capabilities: ORD, indexes: OPE_IDX, samples: TS_S },
  // numeric
  'public.eql_v3_numeric': { builder: types.Numeric, ColumnClass: EncryptedNumericColumn, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: NUMERIC_S, errorSamples: NUM_ERR },
  'public.eql_v3_numeric_eq': { builder: types.NumericEq, ColumnClass: EncryptedNumericEqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: NUMERIC_S, errorSamples: NUM_ERR },
  'public.eql_v3_numeric_ord_ore': { builder: types.NumericOrdOre, ColumnClass: EncryptedNumericOrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: NUMERIC_S, errorSamples: NUM_ERR },
  'public.eql_v3_numeric_ord': { builder: types.NumericOrd, ColumnClass: EncryptedNumericOrdColumn, castAs: 'number', capabilities: ORD, indexes: OPE_IDX, samples: NUMERIC_S, errorSamples: NUM_ERR },
  // text
  'public.eql_v3_text': { builder: types.Text, ColumnClass: EncryptedTextColumn, castAs: 'string', capabilities: STORAGE, indexes: NONE, samples: TEXT_S },
  'public.eql_v3_text_eq': { builder: types.TextEq, ColumnClass: EncryptedTextEqColumn, castAs: 'string', capabilities: EQ, indexes: UNIQUE_IDX, samples: TEXT_S },
  'public.eql_v3_text_match': { builder: types.TextMatch, ColumnClass: EncryptedTextMatchColumn, castAs: 'string', capabilities: MATCH_ONLY, indexes: MATCH_IDX, samples: TEXT_S },
  'public.eql_v3_text_ord_ore': { builder: types.TextOrdOre, ColumnClass: EncryptedTextOrdOreColumn, castAs: 'string', capabilities: ORD, indexes: TEXT_ORD_ORE_IDX, samples: TEXT_ORE_S },
  'public.eql_v3_text_ord': { builder: types.TextOrd, ColumnClass: EncryptedTextOrdColumn, castAs: 'string', capabilities: ORD, indexes: TEXT_ORD_IDX, samples: TEXT_ORE_S },
  'public.eql_v3_text_search': { builder: types.TextSearch, ColumnClass: EncryptedTextSearchColumn, castAs: 'string', capabilities: FULL, indexes: TEXT_SEARCH_IDX, samples: TEXT_ORE_S },
  // boolean
  'public.eql_v3_boolean': { builder: types.Boolean, ColumnClass: EncryptedBooleanColumn, castAs: 'boolean', capabilities: STORAGE, indexes: NONE, samples: BOOLEAN_S },
  // real
  'public.eql_v3_real': { builder: types.Real, ColumnClass: EncryptedRealColumn, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: REAL_S, errorSamples: NUM_ERR },
  'public.eql_v3_real_eq': { builder: types.RealEq, ColumnClass: EncryptedRealEqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: REAL_S, errorSamples: NUM_ERR },
  'public.eql_v3_real_ord_ore': { builder: types.RealOrdOre, ColumnClass: EncryptedRealOrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: REAL_S, errorSamples: NUM_ERR },
  'public.eql_v3_real_ord': { builder: types.RealOrd, ColumnClass: EncryptedRealOrdColumn, castAs: 'number', capabilities: ORD, indexes: OPE_IDX, samples: REAL_S, errorSamples: NUM_ERR },
  // double
  'public.eql_v3_double': { builder: types.Double, ColumnClass: EncryptedDoubleColumn, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: DOUBLE_S, errorSamples: NUM_ERR },
  'public.eql_v3_double_eq': { builder: types.DoubleEq, ColumnClass: EncryptedDoubleEqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: DOUBLE_S, errorSamples: NUM_ERR },
  'public.eql_v3_double_ord_ore': { builder: types.DoubleOrdOre, ColumnClass: EncryptedDoubleOrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: DOUBLE_S, errorSamples: NUM_ERR },
  'public.eql_v3_double_ord': { builder: types.DoubleOrd, ColumnClass: EncryptedDoubleOrdColumn, castAs: 'number', capabilities: ORD, indexes: OPE_IDX, samples: DOUBLE_S, errorSamples: NUM_ERR },
} as const satisfies Record<EqlV3TypeName, DomainSpec>
