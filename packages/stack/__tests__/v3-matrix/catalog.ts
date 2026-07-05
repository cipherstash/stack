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
  EncryptedBoolColumn,
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn,
  EncryptedDateOrdOreColumn,
  EncryptedFloat4Column,
  EncryptedFloat4EqColumn,
  EncryptedFloat4OrdColumn,
  EncryptedFloat4OrdOreColumn,
  EncryptedFloat8Column,
  EncryptedFloat8EqColumn,
  EncryptedFloat8OrdColumn,
  EncryptedFloat8OrdOreColumn,
  EncryptedInt2Column,
  EncryptedInt2EqColumn,
  EncryptedInt2OrdColumn,
  EncryptedInt2OrdOreColumn,
  EncryptedInt4Column,
  EncryptedInt4EqColumn,
  EncryptedInt4OrdColumn,
  EncryptedInt4OrdOreColumn,
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn,
  EncryptedNumericOrdOreColumn,
  EncryptedTextColumn,
  EncryptedTextEqColumn,
  EncryptedTextMatchColumn,
  EncryptedTextOrdColumn,
  EncryptedTextOrdOreColumn,
  EncryptedTextSearchColumn,
  EncryptedTimestamptzColumn,
  EncryptedTimestamptzEqColumn,
  EncryptedTimestamptzOrdColumn,
  EncryptedTimestamptzOrdOreColumn,
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
   * tell `int4` from `float8`, and a fractional value on an int-named domain is
   * untested territory (it would truncate against a real narrow PG column).
   */
  samples: ReadonlyArray<string | number | boolean | Date>
  /**
   * Values that MUST fail encryption. Number domains reject `NaN`/`±Infinity`
   * via a global guard; other domains omit this.
   */
  errorSamples?: ReadonlyArray<number>
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
const ORE_IDX: Indexes = { ore: {} }
// Text order domains (`text_ord`, `text_ord_ore`) carry BOTH `hm` (unique) and
// `ob` (ore): their eql_v3 SQL domains require `hm` because text equality is
// HMAC-based, unlike numeric/date order domains which answer equality via `ob`.
const TEXT_ORD_IDX: Indexes = { unique: { token_filters: [] }, ore: {} }
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
  ore: {},
  match: MATCH_BLOCK,
}

// Sample plaintexts per plaintext axis, consumed by `matrix-live.test.ts`.
// Numeric sets are split by domain width: integers (incl. type bounds) for
// int2/int4, fractionals for float4/float8/numeric. See `DomainSpec.samples`.
const INT2_S = [0, -1, 32767, -32768] as const
const INT4_S = [0, -42, 2147483647, -2147483648] as const
const FLOAT4_S = [0, 77.5, -117.25, 0.5] as const
const FLOAT8_S = [0, -117.123456, 1e15, -1e15] as const
const NUMERIC_S = [0, 12345.678, -42, -0.5] as const
const TEXT_S = ['', 'ada@example.com', 'Ada Lovelace'] as const
// Text order domains require a non-empty ORE (`ob`) term to satisfy the real
// Postgres domain checks. Empty-string rejection is covered in matrix-live-pg.
const TEXT_ORD_S = [
  'ada@example.com',
  'grace@example.com',
  'zora@example.org',
] as const
const BOOL_S = [true, false] as const
const DATE_S = [
  new Date('2026-07-01T00:00:00.000Z'),
  new Date('1970-01-01T00:00:00.000Z'),
] as const
// Every number domain rejects these via the global encrypt guard.
const NUM_ERR = [
  Number.NaN,
  Number.POSITIVE_INFINITY,
  Number.NEGATIVE_INFINITY,
] as const

// biome-ignore format: one row per domain reads as a table; keep it dense.
export const V3_MATRIX = {
  // int4
  'eql_v3.int4': { builder: types.Int4, ColumnClass: EncryptedInt4Column, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: INT4_S, errorSamples: NUM_ERR },
  'eql_v3.int4_eq': { builder: types.Int4Eq, ColumnClass: EncryptedInt4EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: INT4_S, errorSamples: NUM_ERR },
  'eql_v3.int4_ord_ore': { builder: types.Int4OrdOre, ColumnClass: EncryptedInt4OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: INT4_S, errorSamples: NUM_ERR },
  'eql_v3.int4_ord': { builder: types.Int4Ord, ColumnClass: EncryptedInt4OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: INT4_S, errorSamples: NUM_ERR },
  // int2
  'eql_v3.int2': { builder: types.Int2, ColumnClass: EncryptedInt2Column, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: INT2_S, errorSamples: NUM_ERR },
  'eql_v3.int2_eq': { builder: types.Int2Eq, ColumnClass: EncryptedInt2EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: INT2_S, errorSamples: NUM_ERR },
  'eql_v3.int2_ord_ore': { builder: types.Int2OrdOre, ColumnClass: EncryptedInt2OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: INT2_S, errorSamples: NUM_ERR },
  'eql_v3.int2_ord': { builder: types.Int2Ord, ColumnClass: EncryptedInt2OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: INT2_S, errorSamples: NUM_ERR },
  // date
  'eql_v3.date': { builder: types.Date, ColumnClass: EncryptedDateColumn, castAs: 'date', capabilities: STORAGE, indexes: NONE, samples: DATE_S },
  'eql_v3.date_eq': { builder: types.DateEq, ColumnClass: EncryptedDateEqColumn, castAs: 'date', capabilities: EQ, indexes: UNIQUE_IDX, samples: DATE_S },
  'eql_v3.date_ord_ore': { builder: types.DateOrdOre, ColumnClass: EncryptedDateOrdOreColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX, samples: DATE_S },
  'eql_v3.date_ord': { builder: types.DateOrd, ColumnClass: EncryptedDateOrdColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX, samples: DATE_S },
  // timestamptz
  'eql_v3.timestamptz': { builder: types.Timestamptz, ColumnClass: EncryptedTimestamptzColumn, castAs: 'date', capabilities: STORAGE, indexes: NONE, samples: DATE_S },
  'eql_v3.timestamptz_eq': { builder: types.TimestamptzEq, ColumnClass: EncryptedTimestamptzEqColumn, castAs: 'date', capabilities: EQ, indexes: UNIQUE_IDX, samples: DATE_S },
  'eql_v3.timestamptz_ord_ore': { builder: types.TimestamptzOrdOre, ColumnClass: EncryptedTimestamptzOrdOreColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX, samples: DATE_S },
  'eql_v3.timestamptz_ord': { builder: types.TimestamptzOrd, ColumnClass: EncryptedTimestamptzOrdColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX, samples: DATE_S },
  // numeric
  'eql_v3.numeric': { builder: types.Numeric, ColumnClass: EncryptedNumericColumn, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: NUMERIC_S, errorSamples: NUM_ERR },
  'eql_v3.numeric_eq': { builder: types.NumericEq, ColumnClass: EncryptedNumericEqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: NUMERIC_S, errorSamples: NUM_ERR },
  'eql_v3.numeric_ord_ore': { builder: types.NumericOrdOre, ColumnClass: EncryptedNumericOrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: NUMERIC_S, errorSamples: NUM_ERR },
  'eql_v3.numeric_ord': { builder: types.NumericOrd, ColumnClass: EncryptedNumericOrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: NUMERIC_S, errorSamples: NUM_ERR },
  // text
  'eql_v3.text': { builder: types.Text, ColumnClass: EncryptedTextColumn, castAs: 'string', capabilities: STORAGE, indexes: NONE, samples: TEXT_S },
  'eql_v3.text_eq': { builder: types.TextEq, ColumnClass: EncryptedTextEqColumn, castAs: 'string', capabilities: EQ, indexes: UNIQUE_IDX, samples: TEXT_S },
  'eql_v3.text_match': { builder: types.TextMatch, ColumnClass: EncryptedTextMatchColumn, castAs: 'string', capabilities: MATCH_ONLY, indexes: MATCH_IDX, samples: TEXT_S },
  'eql_v3.text_ord_ore': { builder: types.TextOrdOre, ColumnClass: EncryptedTextOrdOreColumn, castAs: 'string', capabilities: ORD, indexes: TEXT_ORD_IDX, samples: TEXT_ORD_S },
  'eql_v3.text_ord': { builder: types.TextOrd, ColumnClass: EncryptedTextOrdColumn, castAs: 'string', capabilities: ORD, indexes: TEXT_ORD_IDX, samples: TEXT_ORD_S },
  'eql_v3.text_search': { builder: types.TextSearch, ColumnClass: EncryptedTextSearchColumn, castAs: 'string', capabilities: FULL, indexes: TEXT_SEARCH_IDX, samples: TEXT_S },
  // bool
  'eql_v3.bool': { builder: types.Bool, ColumnClass: EncryptedBoolColumn, castAs: 'boolean', capabilities: STORAGE, indexes: NONE, samples: BOOL_S },
  // float4
  'eql_v3.float4': { builder: types.Float4, ColumnClass: EncryptedFloat4Column, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: FLOAT4_S, errorSamples: NUM_ERR },
  'eql_v3.float4_eq': { builder: types.Float4Eq, ColumnClass: EncryptedFloat4EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: FLOAT4_S, errorSamples: NUM_ERR },
  'eql_v3.float4_ord_ore': { builder: types.Float4OrdOre, ColumnClass: EncryptedFloat4OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: FLOAT4_S, errorSamples: NUM_ERR },
  'eql_v3.float4_ord': { builder: types.Float4Ord, ColumnClass: EncryptedFloat4OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: FLOAT4_S, errorSamples: NUM_ERR },
  // float8
  'eql_v3.float8': { builder: types.Float8, ColumnClass: EncryptedFloat8Column, castAs: 'number', capabilities: STORAGE, indexes: NONE, samples: FLOAT8_S, errorSamples: NUM_ERR },
  'eql_v3.float8_eq': { builder: types.Float8Eq, ColumnClass: EncryptedFloat8EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX, samples: FLOAT8_S, errorSamples: NUM_ERR },
  'eql_v3.float8_ord_ore': { builder: types.Float8OrdOre, ColumnClass: EncryptedFloat8OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: FLOAT8_S, errorSamples: NUM_ERR },
  'eql_v3.float8_ord': { builder: types.Float8Ord, ColumnClass: EncryptedFloat8OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX, samples: FLOAT8_S, errorSamples: NUM_ERR },
} as const satisfies Record<EqlV3TypeName, DomainSpec>
