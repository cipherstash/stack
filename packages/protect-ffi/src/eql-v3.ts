// Hand-written barrel over the vendored (generated) EQL v3 payload types in
// src/eql-v3-types/. Assembles the public unions and renames the few types
// whose names would clash with the v2 exports in index.cts (`Identifier`,
// `SteVecEntry`) or shadow a global (`Boolean`, `Date`).

import type { Bigint } from './eql-v3-types/Bigint.js'
import type { BigintEq } from './eql-v3-types/BigintEq.js'
import type { BigintEqQuery } from './eql-v3-types/BigintEqQuery.js'
import type { BigintOrd } from './eql-v3-types/BigintOrd.js'
import type { BigintOrdOpe } from './eql-v3-types/BigintOrdOpe.js'
import type { BigintOrdOpeQuery } from './eql-v3-types/BigintOrdOpeQuery.js'
import type { BigintOrdOre } from './eql-v3-types/BigintOrdOre.js'
import type { BigintOrdOreQuery } from './eql-v3-types/BigintOrdOreQuery.js'
import type { BigintOrdQuery } from './eql-v3-types/BigintOrdQuery.js'
import type { Boolean as EqlV3Boolean } from './eql-v3-types/Boolean.js'
import type { Date as EqlV3Date } from './eql-v3-types/Date.js'
import type { DateEq } from './eql-v3-types/DateEq.js'
import type { DateEqQuery } from './eql-v3-types/DateEqQuery.js'
import type { DateOrd } from './eql-v3-types/DateOrd.js'
import type { DateOrdOpe } from './eql-v3-types/DateOrdOpe.js'
import type { DateOrdOpeQuery } from './eql-v3-types/DateOrdOpeQuery.js'
import type { DateOrdOre } from './eql-v3-types/DateOrdOre.js'
import type { DateOrdOreQuery } from './eql-v3-types/DateOrdOreQuery.js'
import type { DateOrdQuery } from './eql-v3-types/DateOrdQuery.js'
import type { Double } from './eql-v3-types/Double.js'
import type { DoubleEq } from './eql-v3-types/DoubleEq.js'
import type { DoubleEqQuery } from './eql-v3-types/DoubleEqQuery.js'
import type { DoubleOrd } from './eql-v3-types/DoubleOrd.js'
import type { DoubleOrdOpe } from './eql-v3-types/DoubleOrdOpe.js'
import type { DoubleOrdOpeQuery } from './eql-v3-types/DoubleOrdOpeQuery.js'
import type { DoubleOrdOre } from './eql-v3-types/DoubleOrdOre.js'
import type { DoubleOrdOreQuery } from './eql-v3-types/DoubleOrdOreQuery.js'
import type { DoubleOrdQuery } from './eql-v3-types/DoubleOrdQuery.js'
import type { Integer } from './eql-v3-types/Integer.js'
import type { IntegerEq } from './eql-v3-types/IntegerEq.js'
import type { IntegerEqQuery } from './eql-v3-types/IntegerEqQuery.js'
import type { IntegerOrd } from './eql-v3-types/IntegerOrd.js'
import type { IntegerOrdOpe } from './eql-v3-types/IntegerOrdOpe.js'
import type { IntegerOrdOpeQuery } from './eql-v3-types/IntegerOrdOpeQuery.js'
import type { IntegerOrdOre } from './eql-v3-types/IntegerOrdOre.js'
import type { IntegerOrdOreQuery } from './eql-v3-types/IntegerOrdOreQuery.js'
import type { IntegerOrdQuery } from './eql-v3-types/IntegerOrdQuery.js'
import type { Numeric } from './eql-v3-types/Numeric.js'
import type { NumericEq } from './eql-v3-types/NumericEq.js'
import type { NumericEqQuery } from './eql-v3-types/NumericEqQuery.js'
import type { NumericOrd } from './eql-v3-types/NumericOrd.js'
import type { NumericOrdOpe } from './eql-v3-types/NumericOrdOpe.js'
import type { NumericOrdOpeQuery } from './eql-v3-types/NumericOrdOpeQuery.js'
import type { NumericOrdOre } from './eql-v3-types/NumericOrdOre.js'
import type { NumericOrdOreQuery } from './eql-v3-types/NumericOrdOreQuery.js'
import type { NumericOrdQuery } from './eql-v3-types/NumericOrdQuery.js'
import type { Real } from './eql-v3-types/Real.js'
import type { RealEq } from './eql-v3-types/RealEq.js'
import type { RealEqQuery } from './eql-v3-types/RealEqQuery.js'
import type { RealOrd } from './eql-v3-types/RealOrd.js'
import type { RealOrdOpe } from './eql-v3-types/RealOrdOpe.js'
import type { RealOrdOpeQuery } from './eql-v3-types/RealOrdOpeQuery.js'
import type { RealOrdOre } from './eql-v3-types/RealOrdOre.js'
import type { RealOrdOreQuery } from './eql-v3-types/RealOrdOreQuery.js'
import type { RealOrdQuery } from './eql-v3-types/RealOrdQuery.js'
import type { Selector } from './eql-v3-types/Selector.js'
import type { Smallint } from './eql-v3-types/Smallint.js'
import type { SmallintEq } from './eql-v3-types/SmallintEq.js'
import type { SmallintEqQuery } from './eql-v3-types/SmallintEqQuery.js'
import type { SmallintOrd } from './eql-v3-types/SmallintOrd.js'
import type { SmallintOrdOpe } from './eql-v3-types/SmallintOrdOpe.js'
import type { SmallintOrdOpeQuery } from './eql-v3-types/SmallintOrdOpeQuery.js'
import type { SmallintOrdOre } from './eql-v3-types/SmallintOrdOre.js'
import type { SmallintOrdOreQuery } from './eql-v3-types/SmallintOrdOreQuery.js'
import type { SmallintOrdQuery } from './eql-v3-types/SmallintOrdQuery.js'
import type { SteVecDocument } from './eql-v3-types/SteVecDocument.js'
import type { SteVecQuery } from './eql-v3-types/SteVecQuery.js'
import type { Text } from './eql-v3-types/Text.js'
import type { TextEq } from './eql-v3-types/TextEq.js'
import type { TextEqQuery } from './eql-v3-types/TextEqQuery.js'
import type { TextMatch } from './eql-v3-types/TextMatch.js'
import type { TextMatchQuery } from './eql-v3-types/TextMatchQuery.js'
import type { TextOrd } from './eql-v3-types/TextOrd.js'
import type { TextOrdOpe } from './eql-v3-types/TextOrdOpe.js'
import type { TextOrdOpeQuery } from './eql-v3-types/TextOrdOpeQuery.js'
import type { TextOrdOre } from './eql-v3-types/TextOrdOre.js'
import type { TextOrdOreQuery } from './eql-v3-types/TextOrdOreQuery.js'
import type { TextOrdQuery } from './eql-v3-types/TextOrdQuery.js'
import type { TextSearch } from './eql-v3-types/TextSearch.js'
import type { TextSearchOre } from './eql-v3-types/TextSearchOre.js'
import type { TextSearchOreQuery } from './eql-v3-types/TextSearchOreQuery.js'
import type { TextSearchQuery } from './eql-v3-types/TextSearchQuery.js'
import type { Timestamp } from './eql-v3-types/Timestamp.js'
import type { TimestampEq } from './eql-v3-types/TimestampEq.js'
import type { TimestampEqQuery } from './eql-v3-types/TimestampEqQuery.js'
import type { TimestampOrd } from './eql-v3-types/TimestampOrd.js'
import type { TimestampOrdOpe } from './eql-v3-types/TimestampOrdOpe.js'
import type { TimestampOrdOpeQuery } from './eql-v3-types/TimestampOrdOpeQuery.js'
import type { TimestampOrdOre } from './eql-v3-types/TimestampOrdOre.js'
import type { TimestampOrdOreQuery } from './eql-v3-types/TimestampOrdOreQuery.js'
import type { TimestampOrdQuery } from './eql-v3-types/TimestampOrdQuery.js'

// Wire-field newtypes and shared envelope pieces.
export type { BloomFilter } from './eql-v3-types/BloomFilter.js'
export type { Ciphertext } from './eql-v3-types/Ciphertext.js'
export type { EntryCiphertext } from './eql-v3-types/EntryCiphertext.js'
export type { Hmac256 } from './eql-v3-types/Hmac256.js'
export type { Identifier as EqlV3Identifier } from './eql-v3-types/Identifier.js'
export type { KeyHeader } from './eql-v3-types/KeyHeader.js'
export type { OpeCllw } from './eql-v3-types/OpeCllw.js'
export type { OreBlock256 } from './eql-v3-types/OreBlock256.js'
export type { SchemaVersion } from './eql-v3-types/SchemaVersion.js'
export type { Selector } from './eql-v3-types/Selector.js'

// SteVec (encrypted JSONB) shapes.
export type { SteVecDocument } from './eql-v3-types/SteVecDocument.js'
export type { SteVecEntry as EqlV3SteVecEntry } from './eql-v3-types/SteVecEntry.js'
export type { SteVecForm } from './eql-v3-types/SteVecForm.js'
export type { SteVecQuery } from './eql-v3-types/SteVecQuery.js'
export type { SteVecQueryEntry } from './eql-v3-types/SteVecQueryEntry.js'

// Scalar domain payloads.
export type {
  Bigint,
  BigintEq,
  BigintOrd,
  BigintOrdOpe,
  BigintOrdOre,
  EqlV3Boolean,
  EqlV3Date,
  DateEq,
  DateOrd,
  DateOrdOpe,
  DateOrdOre,
  Double,
  DoubleEq,
  DoubleOrd,
  DoubleOrdOpe,
  DoubleOrdOre,
  Integer,
  IntegerEq,
  IntegerOrd,
  IntegerOrdOpe,
  IntegerOrdOre,
  Numeric,
  NumericEq,
  NumericOrd,
  NumericOrdOpe,
  NumericOrdOre,
  Real,
  RealEq,
  RealOrd,
  RealOrdOpe,
  RealOrdOre,
  Smallint,
  SmallintEq,
  SmallintOrd,
  SmallintOrdOpe,
  SmallintOrdOre,
  Text,
  TextEq,
  TextMatch,
  TextOrd,
  TextOrdOpe,
  TextOrdOre,
  TextSearch,
  TextSearchOre,
  Timestamp,
  TimestampEq,
  TimestampOrd,
  TimestampOrdOpe,
  TimestampOrdOre,
}

// Scalar query-operand payloads (term-only twins of the domains above).
export type {
  BigintEqQuery,
  BigintOrdOpeQuery,
  BigintOrdOreQuery,
  BigintOrdQuery,
  DateEqQuery,
  DateOrdOpeQuery,
  DateOrdOreQuery,
  DateOrdQuery,
  DoubleEqQuery,
  DoubleOrdOpeQuery,
  DoubleOrdOreQuery,
  DoubleOrdQuery,
  IntegerEqQuery,
  IntegerOrdOpeQuery,
  IntegerOrdOreQuery,
  IntegerOrdQuery,
  NumericEqQuery,
  NumericOrdOpeQuery,
  NumericOrdOreQuery,
  NumericOrdQuery,
  RealEqQuery,
  RealOrdOpeQuery,
  RealOrdOreQuery,
  RealOrdQuery,
  SmallintEqQuery,
  SmallintOrdOpeQuery,
  SmallintOrdOreQuery,
  SmallintOrdQuery,
  TextEqQuery,
  TextMatchQuery,
  TextOrdOpeQuery,
  TextOrdOreQuery,
  TextOrdQuery,
  TextSearchOreQuery,
  TextSearchQuery,
  TimestampEqQuery,
  TimestampOrdOpeQuery,
  TimestampOrdOreQuery,
  TimestampOrdQuery,
}

/**
 * Every flat scalar EQL v3 storage payload (`{v: 3, i, c, <terms>}`, one
 * struct per `eql_v3` scalar domain).
 */
export type EncryptedV3Scalar =
  | Bigint
  | BigintEq
  | BigintOrd
  | BigintOrdOpe
  | BigintOrdOre
  | EqlV3Boolean
  | EqlV3Date
  | DateEq
  | DateOrd
  | DateOrdOpe
  | DateOrdOre
  | Double
  | DoubleEq
  | DoubleOrd
  | DoubleOrdOpe
  | DoubleOrdOre
  | Integer
  | IntegerEq
  | IntegerOrd
  | IntegerOrdOpe
  | IntegerOrdOre
  | Numeric
  | NumericEq
  | NumericOrd
  | NumericOrdOpe
  | NumericOrdOre
  | Real
  | RealEq
  | RealOrd
  | RealOrdOpe
  | RealOrdOre
  | Smallint
  | SmallintEq
  | SmallintOrd
  | SmallintOrdOpe
  | SmallintOrdOre
  | Text
  | TextEq
  | TextMatch
  | TextOrd
  | TextOrdOpe
  | TextOrdOre
  | TextSearch
  | TextSearchOre
  | Timestamp
  | TimestampEq
  | TimestampOrd
  | TimestampOrdOpe
  | TimestampOrdOre

/**
 * EQL v3 **storage** payload — returned by `encrypt` / `encryptBulk` when the
 * client was created with `eqlVersion: 3`.
 *
 * Scalars carry no `k` discriminator: they are flat
 * (`{v: 3, i, c, <terms>}`, terms depending on the column's `eql_v3` domain).
 * Encrypted JSONB is a {@link SteVecDocument}, which keeps the `k: "sv"`
 * form discriminator (`{v: 3, k: "sv", i, sv: [...]}`).
 * The record ciphertext lives at `c` on scalars and at `sv[0].c` on SteVec
 * documents (`sv[0]` is always the decryption root).
 */
export type EncryptedV3 = EncryptedV3Scalar | SteVecDocument

/**
 * Every scalar EQL v3 query operand — the term-only twin
 * (`{v: 3, i, <terms>}`, no `c`) of the column's storage domain, cast in SQL
 * to `eql_v3.query_<name>`. The operand always carries ALL the column
 * domain's terms regardless of the queried `indexType` (the SQL operators
 * pair each column domain only with its same-name query twin).
 */
export type EncryptedV3ScalarQuery =
  | BigintEqQuery
  | BigintOrdOpeQuery
  | BigintOrdOreQuery
  | BigintOrdQuery
  | DateEqQuery
  | DateOrdOpeQuery
  | DateOrdOreQuery
  | DateOrdQuery
  | DoubleEqQuery
  | DoubleOrdOpeQuery
  | DoubleOrdOreQuery
  | DoubleOrdQuery
  | IntegerEqQuery
  | IntegerOrdOpeQuery
  | IntegerOrdOreQuery
  | IntegerOrdQuery
  | NumericEqQuery
  | NumericOrdOpeQuery
  | NumericOrdOreQuery
  | NumericOrdQuery
  | RealEqQuery
  | RealOrdOpeQuery
  | RealOrdOreQuery
  | RealOrdQuery
  | SmallintEqQuery
  | SmallintOrdOpeQuery
  | SmallintOrdOreQuery
  | SmallintOrdQuery
  | TextEqQuery
  | TextMatchQuery
  | TextOrdOpeQuery
  | TextOrdOreQuery
  | TextOrdQuery
  | TextSearchOreQuery
  | TextSearchQuery
  | TimestampEqQuery
  | TimestampOrdOpeQuery
  | TimestampOrdOreQuery
  | TimestampOrdQuery

/**
 * EQL v3 **query** payload — returned by `encryptQuery` / `encryptQueryBulk`
 * under `eqlVersion: 3`:
 *
 * - Scalar queries: an {@link EncryptedV3ScalarQuery} term-only operand —
 *   bind it with `WHERE col = $1::jsonb::eql_v3.query_<name>` (or the
 *   ordering / containment operator the domain supports).
 * - JSONB containment queries: a {@link SteVecQuery} needle — bind it with
 *   `WHERE doc @> $1::jsonb::eql_v3.query_json`.
 * - JSONB selector (path) queries: the bare {@link Selector} hash (a
 *   string) — there is no encrypted-selector envelope in v3; bind it as the
 *   `text` argument of `->` / `->>` (`SELECT doc -> $1`).
 */
export type EncryptedV3Query = EncryptedV3ScalarQuery | SteVecQuery | Selector
