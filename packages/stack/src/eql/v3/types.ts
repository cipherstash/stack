import {
  BIGINT,
  BIGINT_EQ,
  BIGINT_ORD,
  BIGINT_ORD_ORE,
  BOOLEAN,
  DATE,
  DATE_EQ,
  DATE_ORD,
  DATE_ORD_ORE,
  DOUBLE,
  DOUBLE_EQ,
  DOUBLE_ORD,
  DOUBLE_ORD_ORE,
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
  INTEGER,
  INTEGER_EQ,
  INTEGER_ORD,
  INTEGER_ORD_ORE,
  NUMERIC,
  NUMERIC_EQ,
  NUMERIC_ORD,
  NUMERIC_ORD_ORE,
  REAL,
  REAL_EQ,
  REAL_ORD,
  REAL_ORD_ORE,
  SMALLINT,
  SMALLINT_EQ,
  SMALLINT_ORD,
  SMALLINT_ORD_ORE,
  TEXT,
  TEXT_EQ,
  TEXT_MATCH,
  TEXT_ORD,
  TEXT_ORD_ORE,
  TIMESTAMP,
  TIMESTAMP_EQ,
  TIMESTAMP_ORD,
  TIMESTAMP_ORD_ORE,
  type V3ColumnFactory,
} from './columns'

/**
 * The v3 column-type namespace. Each member is a public, semantic factory name
 * for a concrete EQL v3 column. Most members mirror the underlying domain name;
 * JS-friendly scalar names map to Postgres concrete domains, e.g.
 * `types.IntegerOrd` builds a `public.integer_ord` column and `types.Boolean`
 * builds a `public.boolean` column.
 *
 * If these factory names stop matching the emitted capability/domain surface,
 * the stack package is out of sync with the underlying EQL build. That is a
 * version mismatch, not a harmless naming drift.
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
 *   weight:    types.IntegerOrd('weight'),         // order + range
 *   createdAt: types.Timestamp('created_at'), // storage only
 * })
 * ```
 *
 * `types.TextSearch` is fully described by its type — like every other domain,
 * it has no capability-bearing or tuning chain. Its match index is always
 * emitted with the default configuration; run a free-text query by passing
 * `queryType: 'freeTextSearch'` to `encryptQuery`.
 */
export const types = {
  // integer
  Integer: (name: string) => new EncryptedIntegerColumn(name, INTEGER),
  IntegerEq: (name: string) => new EncryptedIntegerEqColumn(name, INTEGER_EQ),
  IntegerOrdOre: (name: string) =>
    new EncryptedIntegerOrdOreColumn(name, INTEGER_ORD_ORE),
  IntegerOrd: (name: string) =>
    new EncryptedIntegerOrdColumn(name, INTEGER_ORD),

  // smallint
  Smallint: (name: string) => new EncryptedSmallintColumn(name, SMALLINT),
  SmallintEq: (name: string) =>
    new EncryptedSmallintEqColumn(name, SMALLINT_EQ),
  SmallintOrdOre: (name: string) =>
    new EncryptedSmallintOrdOreColumn(name, SMALLINT_ORD_ORE),
  SmallintOrd: (name: string) =>
    new EncryptedSmallintOrdColumn(name, SMALLINT_ORD),

  // bigint (int8) — plaintext is a JS `bigint`, round-tripped losslessly by
  // the native protect-ffi boundary (see ./columns)
  Bigint: (name: string) => new EncryptedBigintColumn(name, BIGINT),
  BigintEq: (name: string) => new EncryptedBigintEqColumn(name, BIGINT_EQ),
  BigintOrdOre: (name: string) =>
    new EncryptedBigintOrdOreColumn(name, BIGINT_ORD_ORE),
  BigintOrd: (name: string) => new EncryptedBigintOrdColumn(name, BIGINT_ORD),

  // date
  Date: (name: string) => new EncryptedDateColumn(name, DATE),
  DateEq: (name: string) => new EncryptedDateEqColumn(name, DATE_EQ),
  DateOrdOre: (name: string) =>
    new EncryptedDateOrdOreColumn(name, DATE_ORD_ORE),
  DateOrd: (name: string) => new EncryptedDateOrdColumn(name, DATE_ORD),

  // timestamp
  Timestamp: (name: string) => new EncryptedTimestampColumn(name, TIMESTAMP),
  TimestampEq: (name: string) =>
    new EncryptedTimestampEqColumn(name, TIMESTAMP_EQ),
  TimestampOrdOre: (name: string) =>
    new EncryptedTimestampOrdOreColumn(name, TIMESTAMP_ORD_ORE),
  TimestampOrd: (name: string) =>
    new EncryptedTimestampOrdColumn(name, TIMESTAMP_ORD),

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
  TextMatch: (name: string) => new EncryptedTextMatchColumn(name, TEXT_MATCH),
  TextOrdOre: (name: string) =>
    new EncryptedTextOrdOreColumn(name, TEXT_ORD_ORE),
  TextOrd: (name: string) => new EncryptedTextOrdColumn(name, TEXT_ORD),
  TextSearch: (name: string) => new EncryptedTextSearchColumn(name),

  // boolean
  Boolean: (name: string) => new EncryptedBooleanColumn(name, BOOLEAN),

  // real
  Real: (name: string) => new EncryptedRealColumn(name, REAL),
  RealEq: (name: string) => new EncryptedRealEqColumn(name, REAL_EQ),
  RealOrdOre: (name: string) =>
    new EncryptedRealOrdOreColumn(name, REAL_ORD_ORE),
  RealOrd: (name: string) => new EncryptedRealOrdColumn(name, REAL_ORD),

  // double
  Double: (name: string) => new EncryptedDoubleColumn(name, DOUBLE),
  DoubleEq: (name: string) => new EncryptedDoubleEqColumn(name, DOUBLE_EQ),
  DoubleOrdOre: (name: string) =>
    new EncryptedDoubleOrdOreColumn(name, DOUBLE_ORD_ORE),
  DoubleOrd: (name: string) => new EncryptedDoubleOrdColumn(name, DOUBLE_ORD),
  // `satisfies` is load-bearing, not decoration: `DOMAIN_REGISTRY` derives itself
  // by calling every value here at module load. A non-factory export would throw
  // during module evaluation and take the supabase introspect/schema-build/verify
  // path down with it. This turns that into a compile error at the offending line.
  // `as const` applies first, so literal key inference is preserved.
} as const satisfies Record<string, V3ColumnFactory>
