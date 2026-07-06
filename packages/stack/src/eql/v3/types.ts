import {
  BOOL,
  DATE,
  DATE_EQ,
  DATE_ORD,
  DATE_ORD_ORE,
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
  FLOAT4,
  FLOAT4_EQ,
  FLOAT4_ORD,
  FLOAT4_ORD_ORE,
  FLOAT8,
  FLOAT8_EQ,
  FLOAT8_ORD,
  FLOAT8_ORD_ORE,
  INT2,
  INT2_EQ,
  INT2_ORD,
  INT2_ORD_ORE,
  INT4,
  INT4_EQ,
  INT4_ORD,
  INT4_ORD_ORE,
  NUMERIC,
  NUMERIC_EQ,
  NUMERIC_ORD,
  NUMERIC_ORD_ORE,
  TEXT,
  TEXT_EQ,
  TEXT_ORD,
  TEXT_ORD_ORE,
  TIMESTAMPTZ,
  TIMESTAMPTZ_EQ,
  TIMESTAMPTZ_ORD,
  TIMESTAMPTZ_ORD_ORE,
} from './columns'

/**
 * The v3 column-type namespace. Each member is a factory that builds a concrete
 * EQL v3 column; the member name mirrors the underlying `eql_v3.<name>` domain
 * (strip the `eql_v3.` prefix, PascalCase each `_`-separated segment). So
 * `types.TextEq('actor')` builds an `eql_v3.text_eq` column, `types.Int4Ord`
 * an `eql_v3.int4_ord`, `types.Timestamptz` an `eql_v3.timestamptz`, and so on.
 *
 * Each factory returns the CONCRETE column class instance (never the widened
 * `AnyEncryptedV3Column`) so per-column plaintext / query-capability inference
 * stays precise.
 *
 * ```ts
 * import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
 *
 * const events = encryptedTable('events', {
 *   actor:     types.TextEq('actor'),           // equality
 *   weight:    types.Int4Ord('weight'),         // order + range
 *   createdAt: types.Timestamptz('created_at'), // storage only
 * })
 * ```
 *
 * `types.TextSearch` keeps the chainable `.freeTextSearch(opts)` tuner (the
 * only capability-bearing chain — every other domain is fully described by its
 * type). int8/bigint domains are intentionally absent pending lossless FFI
 * round-tripping (see ./columns).
 */
export const types = {
  // int4
  Int4: (name: string) => new EncryptedInt4Column(name, INT4),
  Int4Eq: (name: string) => new EncryptedInt4EqColumn(name, INT4_EQ),
  Int4OrdOre: (name: string) =>
    new EncryptedInt4OrdOreColumn(name, INT4_ORD_ORE),
  Int4Ord: (name: string) => new EncryptedInt4OrdColumn(name, INT4_ORD),

  // int2
  Int2: (name: string) => new EncryptedInt2Column(name, INT2),
  Int2Eq: (name: string) => new EncryptedInt2EqColumn(name, INT2_EQ),
  Int2OrdOre: (name: string) =>
    new EncryptedInt2OrdOreColumn(name, INT2_ORD_ORE),
  Int2Ord: (name: string) => new EncryptedInt2OrdColumn(name, INT2_ORD),

  // date
  Date: (name: string) => new EncryptedDateColumn(name, DATE),
  DateEq: (name: string) => new EncryptedDateEqColumn(name, DATE_EQ),
  DateOrdOre: (name: string) =>
    new EncryptedDateOrdOreColumn(name, DATE_ORD_ORE),
  DateOrd: (name: string) => new EncryptedDateOrdColumn(name, DATE_ORD),

  // timestamptz
  Timestamptz: (name: string) =>
    new EncryptedTimestamptzColumn(name, TIMESTAMPTZ),
  TimestamptzEq: (name: string) =>
    new EncryptedTimestamptzEqColumn(name, TIMESTAMPTZ_EQ),
  TimestamptzOrdOre: (name: string) =>
    new EncryptedTimestamptzOrdOreColumn(name, TIMESTAMPTZ_ORD_ORE),
  TimestamptzOrd: (name: string) =>
    new EncryptedTimestamptzOrdColumn(name, TIMESTAMPTZ_ORD),

  // numeric
  Numeric: (name: string) => new EncryptedNumericColumn(name, NUMERIC),
  NumericEq: (name: string) => new EncryptedNumericEqColumn(name, NUMERIC_EQ),
  NumericOrdOre: (name: string) =>
    new EncryptedNumericOrdOreColumn(name, NUMERIC_ORD_ORE),
  NumericOrd: (name: string) =>
    new EncryptedNumericOrdColumn(name, NUMERIC_ORD),

  // text
  Text: (name: string) => new EncryptedTextColumn(name, TEXT),
  TextEq: (name: string) => new EncryptedTextEqColumn(name, TEXT_EQ),
  TextMatch: (name: string) => new EncryptedTextMatchColumn(name),
  TextOrdOre: (name: string) =>
    new EncryptedTextOrdOreColumn(name, TEXT_ORD_ORE),
  TextOrd: (name: string) => new EncryptedTextOrdColumn(name, TEXT_ORD),
  TextSearch: (name: string) => new EncryptedTextSearchColumn(name),

  // bool
  Bool: (name: string) => new EncryptedBoolColumn(name, BOOL),

  // float4
  Float4: (name: string) => new EncryptedFloat4Column(name, FLOAT4),
  Float4Eq: (name: string) => new EncryptedFloat4EqColumn(name, FLOAT4_EQ),
  Float4OrdOre: (name: string) =>
    new EncryptedFloat4OrdOreColumn(name, FLOAT4_ORD_ORE),
  Float4Ord: (name: string) => new EncryptedFloat4OrdColumn(name, FLOAT4_ORD),

  // float8
  Float8: (name: string) => new EncryptedFloat8Column(name, FLOAT8),
  Float8Eq: (name: string) => new EncryptedFloat8EqColumn(name, FLOAT8_EQ),
  Float8OrdOre: (name: string) =>
    new EncryptedFloat8OrdOreColumn(name, FLOAT8_ORD_ORE),
  Float8Ord: (name: string) => new EncryptedFloat8OrdColumn(name, FLOAT8_ORD),
} as const
