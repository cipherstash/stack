/**
 * Codec type definitions for the cipherstash extension.
 *
 * Type-only definitions for codec input/output/traits — consumed by
 * the contract emitter when generating an application's
 * `contract.d.ts`. Importing this subpath registers every cipherstash
 * v3 codec id with its `cipherstash:v3-*` markers, so trait-dispatched
 * operators (`eqlGt`, `eqlBetween`, `eqlIn`, …) surface on real model
 * accessors.
 *
 * # Why this is hand-written, not derived via `ExtractCodecTypes`
 *
 * The framework's `ExtractCodecTypes` helper projects descriptor-keyed
 * types via `traits: TTraits[number] & CodecTrait`. The framework's
 * `CodecTrait` is a closed union of built-ins (`'equality'`,
 * `'order'`, `'numeric'`, `'boolean'`, `'textual'`); the cipherstash
 * trait strings (`'cipherstash:equality'`, `'cipherstash:order-and-range'`,
 * `'cipherstash:free-text-search'`, `'cipherstash:searchable-json'`)
 * deliberately sit outside that union (see ADR 214 + the
 * `equality-trait-removal.test.ts` regression — namespacing isolates
 * the cipherstash dispatch surface from framework built-in operators
 * like `eq` that would lower to standard SQL `=`, which is wrong for
 * EQL ciphertexts). Running cipherstash descriptors through
 * `ExtractCodecTypes` would intersect each trait string with
 * `CodecTrait` and collapse to `never`, defeating the whole point of
 * the augmentation.
 *
 * The hand-written shape preserves the literal trait strings so the
 * model accessor's trait-dispatch type-level lookup
 * (`SqlQueryOperationTypes` → `OpMatchesField`) sees the actual
 * cipherstash trait names and surfaces the right operator on the
 * right column.
 *
 * # Output type uses the envelope class
 *
 * Each codec's runtime `decode` returns an `EncryptedEnvelopeBase`
 * subclass instance. The `output` slot here is the envelope class so
 * `FieldOutputTypes['User']['email']` resolves to `EncryptedString`
 * (and the ORM read path returns an envelope the user calls
 * `.decrypt()` on); `input` is the union of the envelope class and
 * the bare plaintext, mirroring the polymorphic argument shapes the
 * `eql*` predicate operators accept (see `src/v3/operators-v3.ts`).
 */

// Type-only imports — the codec-types subpath compiles to an empty
// JS module under tsdown (every import below is elided), so importing
// the envelope classes by type carries no runtime cost in the
// generated `codec-types.mjs` chunk.
import type { EncryptedBigInt } from '../execution/envelope-bigint'
import type { EncryptedBoolean } from '../execution/envelope-boolean'
import type { EncryptedDate } from '../execution/envelope-date'
import type { EncryptedJson } from '../execution/envelope-json'
import type { EncryptedString } from '../execution/envelope-string'
import type { EncryptedNumber } from '../v3/envelope-number'

// ---------------------------------------------------------------------------
// EQL v3 type-level trait vocabulary
// ---------------------------------------------------------------------------
//
// The `cipherstash:v3-*` strings are TYPE-LEVEL MARKERS with no
// runtime counterpart. The v2 and v3 surfaces have DISJOINT method
// names (`cipherstash*` vs the EQL-derived `eql*` — PR #655 review),
// so v3 codec entries carry ONLY the v3 markers and none of the shared
// v2 trait strings:
//
//   - every `eql*` operator in `operation-types.ts` dispatches on a
//     v3 marker, so it surfaces only on v3 columns;
//   - every v2 operator dispatches on a shared v2 trait (or the legacy
//     `cipherstash/string@1` codec-id pin), which no v3 entry carries,
//     so the `cipherstash*` methods never surface on v3 columns.
//
// Type-level visibility therefore never advertises a method the
// column's runtime cannot dispatch.
type V3TraitsNone = never
type V3TraitsEq = 'cipherstash:v3-equality'
type V3TraitsOrd = V3TraitsEq | 'cipherstash:v3-order-and-range'
type V3TraitsMatch = 'cipherstash:v3-free-text-search'
type V3TraitsSearch = V3TraitsOrd | V3TraitsMatch
type V3TraitsJson = 'cipherstash:v3-searchable-json'

/**
 * One v3 codec entry: `input` is the plaintext family or a pre-built
 * envelope; `output` is the envelope class the v3 cell codec's
 * `decode` constructs (per `envelopeTypeNameForCastAs`); `traits` is
 * the type-level dispatch vocabulary above, derived from the domain's
 * intrinsic query capabilities (see `v3/catalog.ts`).
 */
interface V3Codec<Plain, Envelope, Traits> {
  readonly input: Plain | Envelope
  readonly output: Envelope
  readonly traits: Traits
}

export type CodecTypes = {
  // -------------------------------------------------------------------------
  // EQL v3 — one entry per catalog domain (all 40, including the
  // authoring-unexposed `*_ord_ore` variants the codec layer still
  // decodes). Keys are the pinned `CIPHERSTASH_V3_CODEC_IDS` literals
  // (registry key VERBATIM); trait tiers mirror each domain's intrinsic
  // query capabilities exactly (`test/v3/codec-types-v3.test-d.ts` pins
  // both directions of the correspondence).
  // -------------------------------------------------------------------------
  readonly 'cipherstash/eql-v3/eql_v3_integer@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_integer_eq@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_integer_ord_ore@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_integer_ord@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_smallint@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_smallint_eq@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_smallint_ord_ore@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_smallint_ord@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_bigint@1': V3Codec<
    bigint,
    EncryptedBigInt,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_bigint_eq@1': V3Codec<
    bigint,
    EncryptedBigInt,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_bigint_ord_ore@1': V3Codec<
    bigint,
    EncryptedBigInt,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_bigint_ord@1': V3Codec<
    bigint,
    EncryptedBigInt,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_date@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_date_eq@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_date_ord_ore@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_date_ord@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_timestamp@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_timestamp_eq@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_timestamp_ord_ore@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_timestamp_ord@1': V3Codec<
    Date,
    EncryptedDate,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_numeric@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_numeric_eq@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_numeric_ord_ore@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_numeric_ord@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_text@1': V3Codec<
    string,
    EncryptedString,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_text_eq@1': V3Codec<
    string,
    EncryptedString,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_text_match@1': V3Codec<
    string,
    EncryptedString,
    V3TraitsMatch
  >
  readonly 'cipherstash/eql-v3/eql_v3_text_ord_ore@1': V3Codec<
    string,
    EncryptedString,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_text_ord@1': V3Codec<
    string,
    EncryptedString,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_text_search@1': V3Codec<
    string,
    EncryptedString,
    V3TraitsSearch
  >
  readonly 'cipherstash/eql-v3/eql_v3_boolean@1': V3Codec<
    boolean,
    EncryptedBoolean,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_real@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_real_eq@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_real_ord_ore@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_real_ord@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_double@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsNone
  >
  readonly 'cipherstash/eql-v3/eql_v3_double_eq@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsEq
  >
  readonly 'cipherstash/eql-v3/eql_v3_double_ord_ore@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  readonly 'cipherstash/eql-v3/eql_v3_double_ord@1': V3Codec<
    number,
    EncryptedNumber,
    V3TraitsOrd
  >
  // `unknown` subsumes `EncryptedJson` on the input side, but the
  // alias is kept in scope (via the import above) so the codec entry
  // still flags JSON as an envelope-bearing codec at the type-import
  // layer.
  readonly 'cipherstash/eql-v3/eql_v3_json@1': {
    readonly input: unknown
    readonly output: EncryptedJson
    readonly traits: V3TraitsJson
  }
}
