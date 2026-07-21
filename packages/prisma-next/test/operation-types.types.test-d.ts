/**
 * Type-level acceptance tests for `QueryOperationTypes` in
 * `src/types/operation-types.ts` (EQL v3).
 *
 * Mirrors the framework's `OpMatchesField` predicate (defined in
 * `packages/3-extensions/sql-orm-client/src/types.ts`) inline so the
 * matching behaviour can be exercised against the real `CodecTypes`
 * table without pulling in the full ORM model accessor.
 *
 * Pins the v3 dispatch contract: every `eql*` operator surfaces exactly
 * on the v3 columns whose `cipherstash:v3-*` marker tier carries its
 * capability, and on no column without it; storage-only v3 domains
 * (boolean, bare `eql_v3_text`) surface NO operators; and the retired
 * names (`cipherstashJsonContains`, a negated match) are absent.
 *
 * AGENTS.md permits `@ts-expect-error` exclusively in negative
 * type-test files; this is one of them.
 */

import type { CodecTypes as RealCodecTypes } from '../src/types/codec-types'
import type { QueryOperationTypes } from '../src/types/operation-types'

// -- Inline `OpMatchesField` (mirrors the framework definition) --------------

type OpMatchesField<
  Op,
  C extends string,
  Cct extends Record<string, unknown>,
> = Op extends {
  readonly self: infer Self
}
  ? Self extends { readonly codecId: C }
    ? true
    : Self extends { readonly traits: infer R extends readonly string[] }
      ? C extends keyof Cct
        ? Cct[C] extends { readonly traits: infer FT }
          ? [R[number]] extends [FT]
            ? true
            : false
          : false
        : false
      : false
  : false

type Expect<T extends true> = T

// -- EQL v3 dispatch (against the REAL CodecTypes table) ---------------------
//
// The v3 assertions run against the real `CodecTypes` export (which
// carries the 40 v3 entries plus the `cipherstash:v3-*` type-level
// markers), so drift in the real table breaks this file:
//
//   - every `eql*` operator surfaces exactly on the v3 columns whose
//     marker tier carries its capability;
//   - storage-only v3 domains (boolean, bare `eql_v3_text`) surface NO
//     operators at all;
//   - the retired names (`cipherstashJsonContains`, and any negated
//     match) are gone from the operation table entirely.

type RealOps = QueryOperationTypes<RealCodecTypes>
type M3<N extends keyof RealOps, C extends string> = OpMatchesField<
  RealOps[N],
  C,
  RealCodecTypes
>

// Retired names must not re-enter the table: `cipherstashJsonContains`
// was renamed to `eqlJsonContains`, and a negated match must not exist
// under either vocabulary (bloom negation false-negatives).
type RetiredNames = Extract<
  keyof RealOps,
  'cipherstashJsonContains' | 'eqlNotMatch'
>
type _RetiredNamesAbsent = [RetiredNames] extends [never]
  ? true
  : ['operation table resurrects retired names', RetiredNames]
const _retiredNamesAbsent: _RetiredNamesAbsent = true
void _retiredNamesAbsent

// v3 positives: each marker tier surfaces its operator family.
type _v3_eq_search_pos = Expect<
  M3<'eqlEq', 'cipherstash/eql-v3/eql_v3_text_search@1'>
>
type _v3_eq_bigint_eq_pos = Expect<
  M3<'eqlEq', 'cipherstash/eql-v3/eql_v3_bigint_eq@1'>
>
type _v3_in_texteq_pos = Expect<
  M3<'eqlIn', 'cipherstash/eql-v3/eql_v3_text_eq@1'>
>
type _v3_match_search_pos = Expect<
  M3<'eqlMatch', 'cipherstash/eql-v3/eql_v3_text_search@1'>
>
type _v3_match_textmatch_pos = Expect<
  M3<'eqlMatch', 'cipherstash/eql-v3/eql_v3_text_match@1'>
>
type _v3_gt_ord_pos = Expect<
  M3<'eqlGt', 'cipherstash/eql-v3/eql_v3_double_ord@1'>
>
type _v3_jsoncontains_json_pos = Expect<
  M3<'eqlJsonContains', 'cipherstash/eql-v3/eql_v3_json@1'>
>

// v3 negatives: capability tiers gate visibility.
type _v3_eq_boolean_neg = Expect<
  // @ts-expect-error eqlEq must not surface on storage-only eql_v3_boolean.
  M3<'eqlEq', 'cipherstash/eql-v3/eql_v3_boolean@1'>
>
type _v3_eq_text_storage_neg = Expect<
  // @ts-expect-error eqlEq must not surface on storage-only eql_v3_text.
  M3<'eqlEq', 'cipherstash/eql-v3/eql_v3_text@1'>
>
type _v3_match_texteq_neg = Expect<
  // @ts-expect-error eqlMatch must not surface on eql_v3_text_eq (no free-text index).
  M3<'eqlMatch', 'cipherstash/eql-v3/eql_v3_text_eq@1'>
>
type _v3_gt_eqonly_neg = Expect<
  // @ts-expect-error eqlGt must not surface on eql_v3_double_eq (no order/range).
  M3<'eqlGt', 'cipherstash/eql-v3/eql_v3_double_eq@1'>
>
type _v3_in_boolean_neg = Expect<
  // @ts-expect-error eqlIn must not surface on storage-only eql_v3_boolean.
  M3<'eqlIn', 'cipherstash/eql-v3/eql_v3_boolean@1'>
>

// -- Anchor unused type aliases so noUnusedLocals stays happy ---------------

export type _Anchors = [
  _v3_eq_search_pos,
  _v3_eq_bigint_eq_pos,
  _v3_in_texteq_pos,
  _v3_match_search_pos,
  _v3_match_textmatch_pos,
  _v3_gt_ord_pos,
  _v3_jsoncontains_json_pos,
  _v3_eq_boolean_neg,
  _v3_eq_text_storage_neg,
  _v3_match_texteq_neg,
  _v3_gt_eqonly_neg,
  _v3_in_boolean_neg,
]
