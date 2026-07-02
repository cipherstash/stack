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
import type { ColumnSchema } from '@/schema'
import type {
  AnyEncryptedV3Column,
  EqlTypeForColumn,
  QueryCapabilities,
} from '@/schema/v3'
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
  encryptedBoolColumn,
  encryptedDateColumn,
  encryptedDateEqColumn,
  encryptedDateOrdColumn,
  encryptedDateOrdOreColumn,
  encryptedFloat4Column,
  encryptedFloat4EqColumn,
  encryptedFloat4OrdColumn,
  encryptedFloat4OrdOreColumn,
  encryptedFloat8Column,
  encryptedFloat8EqColumn,
  encryptedFloat8OrdColumn,
  encryptedFloat8OrdOreColumn,
  encryptedInt2Column,
  encryptedInt2EqColumn,
  encryptedInt2OrdColumn,
  encryptedInt2OrdOreColumn,
  encryptedInt4Column,
  encryptedInt4EqColumn,
  encryptedInt4OrdColumn,
  encryptedInt4OrdOreColumn,
  encryptedNumericColumn,
  encryptedNumericEqColumn,
  encryptedNumericOrdColumn,
  encryptedNumericOrdOreColumn,
  encryptedTextColumn,
  encryptedTextEqColumn,
  encryptedTextMatchColumn,
  encryptedTextOrdColumn,
  encryptedTextOrdOreColumn,
  encryptedTextSearchColumn,
  encryptedTimestamptzColumn,
  encryptedTimestamptzEqColumn,
  encryptedTimestamptzOrdColumn,
  encryptedTimestamptzOrdOreColumn,
} from '@/schema/v3'

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

// biome-ignore format: one row per domain reads as a table; keep it dense.
export const V3_MATRIX = {
  // int4
  'eql_v3.int4': { builder: encryptedInt4Column, ColumnClass: EncryptedInt4Column, castAs: 'number', capabilities: STORAGE, indexes: NONE },
  'eql_v3.int4_eq': { builder: encryptedInt4EqColumn, ColumnClass: EncryptedInt4EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.int4_ord_ore': { builder: encryptedInt4OrdOreColumn, ColumnClass: EncryptedInt4OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.int4_ord': { builder: encryptedInt4OrdColumn, ColumnClass: EncryptedInt4OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  // int2
  'eql_v3.int2': { builder: encryptedInt2Column, ColumnClass: EncryptedInt2Column, castAs: 'number', capabilities: STORAGE, indexes: NONE },
  'eql_v3.int2_eq': { builder: encryptedInt2EqColumn, ColumnClass: EncryptedInt2EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.int2_ord_ore': { builder: encryptedInt2OrdOreColumn, ColumnClass: EncryptedInt2OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.int2_ord': { builder: encryptedInt2OrdColumn, ColumnClass: EncryptedInt2OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  // date
  'eql_v3.date': { builder: encryptedDateColumn, ColumnClass: EncryptedDateColumn, castAs: 'date', capabilities: STORAGE, indexes: NONE },
  'eql_v3.date_eq': { builder: encryptedDateEqColumn, ColumnClass: EncryptedDateEqColumn, castAs: 'date', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.date_ord_ore': { builder: encryptedDateOrdOreColumn, ColumnClass: EncryptedDateOrdOreColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.date_ord': { builder: encryptedDateOrdColumn, ColumnClass: EncryptedDateOrdColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX },
  // timestamptz
  'eql_v3.timestamptz': { builder: encryptedTimestamptzColumn, ColumnClass: EncryptedTimestamptzColumn, castAs: 'date', capabilities: STORAGE, indexes: NONE },
  'eql_v3.timestamptz_eq': { builder: encryptedTimestamptzEqColumn, ColumnClass: EncryptedTimestamptzEqColumn, castAs: 'date', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.timestamptz_ord_ore': { builder: encryptedTimestamptzOrdOreColumn, ColumnClass: EncryptedTimestamptzOrdOreColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.timestamptz_ord': { builder: encryptedTimestamptzOrdColumn, ColumnClass: EncryptedTimestamptzOrdColumn, castAs: 'date', capabilities: ORD, indexes: ORE_IDX },
  // numeric
  'eql_v3.numeric': { builder: encryptedNumericColumn, ColumnClass: EncryptedNumericColumn, castAs: 'number', capabilities: STORAGE, indexes: NONE },
  'eql_v3.numeric_eq': { builder: encryptedNumericEqColumn, ColumnClass: EncryptedNumericEqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.numeric_ord_ore': { builder: encryptedNumericOrdOreColumn, ColumnClass: EncryptedNumericOrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.numeric_ord': { builder: encryptedNumericOrdColumn, ColumnClass: EncryptedNumericOrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  // text
  'eql_v3.text': { builder: encryptedTextColumn, ColumnClass: EncryptedTextColumn, castAs: 'string', capabilities: STORAGE, indexes: NONE },
  'eql_v3.text_eq': { builder: encryptedTextEqColumn, ColumnClass: EncryptedTextEqColumn, castAs: 'string', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.text_match': { builder: encryptedTextMatchColumn, ColumnClass: EncryptedTextMatchColumn, castAs: 'string', capabilities: MATCH_ONLY, indexes: MATCH_IDX },
  'eql_v3.text_ord_ore': { builder: encryptedTextOrdOreColumn, ColumnClass: EncryptedTextOrdOreColumn, castAs: 'string', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.text_ord': { builder: encryptedTextOrdColumn, ColumnClass: EncryptedTextOrdColumn, castAs: 'string', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.text_search': { builder: encryptedTextSearchColumn, ColumnClass: EncryptedTextSearchColumn, castAs: 'string', capabilities: FULL, indexes: TEXT_SEARCH_IDX },
  // bool
  'eql_v3.bool': { builder: encryptedBoolColumn, ColumnClass: EncryptedBoolColumn, castAs: 'boolean', capabilities: STORAGE, indexes: NONE },
  // float4
  'eql_v3.float4': { builder: encryptedFloat4Column, ColumnClass: EncryptedFloat4Column, castAs: 'number', capabilities: STORAGE, indexes: NONE },
  'eql_v3.float4_eq': { builder: encryptedFloat4EqColumn, ColumnClass: EncryptedFloat4EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.float4_ord_ore': { builder: encryptedFloat4OrdOreColumn, ColumnClass: EncryptedFloat4OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.float4_ord': { builder: encryptedFloat4OrdColumn, ColumnClass: EncryptedFloat4OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  // float8
  'eql_v3.float8': { builder: encryptedFloat8Column, ColumnClass: EncryptedFloat8Column, castAs: 'number', capabilities: STORAGE, indexes: NONE },
  'eql_v3.float8_eq': { builder: encryptedFloat8EqColumn, ColumnClass: EncryptedFloat8EqColumn, castAs: 'number', capabilities: EQ, indexes: UNIQUE_IDX },
  'eql_v3.float8_ord_ore': { builder: encryptedFloat8OrdOreColumn, ColumnClass: EncryptedFloat8OrdOreColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
  'eql_v3.float8_ord': { builder: encryptedFloat8OrdColumn, ColumnClass: EncryptedFloat8OrdColumn, castAs: 'number', capabilities: ORD, indexes: ORE_IDX },
} as const satisfies Record<EqlV3TypeName, DomainSpec>
