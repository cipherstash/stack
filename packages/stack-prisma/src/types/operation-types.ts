/**
 * Operation type definitions for the cipherstash extension (EQL v3).
 *
 * The type-only counterpart to `cipherstashV3QueryOperations()` in
 * `../v3/operators-v3.ts`. Every entry's `self` dispatch shape mirrors
 * the runtime registration 1:1: each `eql*` operator declares
 * `self: { traits: ['cipherstash:v3-*'] }`, and the framework's
 * `OpMatchesField` trait dispatch surfaces the method on every column
 * whose codec id resolves to a `CodecTypes` entry whose `traits` set
 * includes the same marker. The cipherstash-namespaced prefix isolates
 * these from the framework's closed `CodecTrait` union so adding the
 * trait to a cipherstash codec descriptor cannot silently re-attach a
 * framework built-in.
 *
 * The flat `QueryOperationTypes` surface gets composed into the
 * consuming application's generated `contract.d.ts` by the contract
 * emitter, via the `types.queryOperationTypes` import declaration on
 * `cipherstashPackMeta` (`../extension-metadata/descriptor-meta.ts`).
 *
 * Return-codec id is `pg/bool@1` for every predicate operator — pinned
 * to what the runtime impl builds. The framework's predicate machinery
 * looks at the return codec's `'boolean'` trait to decide a value is
 * suitable for a WHERE clause.
 */

import type { Expression } from '@prisma-next/sql-relational-core/expression'

type CodecTypesBase = Record<
  string,
  { readonly input: unknown; readonly output: unknown }
>

type PgBoolReturn = Expression<{ codecId: 'pg/bool@1'; nullable: false }>

/**
 * v3 TYPE-LEVEL marker traits (no runtime counterpart) — carried only
 * by the v3 codec entries in `codec-types.ts` (see the vocabulary
 * comment there). Every `eql*` operator dispatches on a v3 marker, so
 * type-level visibility stays exactly aligned with what each column's
 * runtime can actually execute.
 *
 * Preserving the literal trait strings at the type level is
 * load-bearing: the consuming `OpMatchesField` predicate (in
 * `packages/3-extensions/sql-orm-client/src/types.ts`) reads
 * `Self.traits` and tests `[traits[number]] extends [CT[CodecId]['traits']]`,
 * so widening to the framework's closed `CodecTrait` union (or to
 * `never[]` via intersection) erases the extension's dispatch
 * information. cipherstash's `QueryOperationTypes` therefore declares
 * its entries directly (rather than via the `SqlQueryOperationTypes<CT,
 * T>` wrapper that constrains `T extends Record<string,
 * QueryOperationTypeEntry>`) so the literal trait strings flow through
 * untouched.
 */
type V3EqualityMarker = readonly ['cipherstash:v3-equality']
type V3OrderAndRangeMarker = readonly ['cipherstash:v3-order-and-range']
type V3FreeTextSearchMarker = readonly ['cipherstash:v3-free-text-search']
type V3SearchableJsonMarker = readonly ['cipherstash:v3-searchable-json']

/**
 * Schematic constraint on `self` for a cipherstash predicate. The
 * runtime impl reads `self.returnType.codecId` and dispatches to the
 * matching envelope — accepting any `Expression` here is correct
 * because the surface is column-method autocomplete, not a
 * free-standing helper. The framework's `OpMatchesField` is what
 * restricts visibility to codecs declaring the gating marker; this
 * `self` argument type is irrelevant to that dispatch.
 */
type AnyExpressionLike = Expression<{
  readonly codecId: string
  readonly nullable: boolean
}>

/**
 * Flat operation signatures consumed by the SQL query builder. Read
 * via the `queryOperations` slot on the runtime context to project the
 * cipherstash `eql*` predicate methods onto cipherstash column
 * accessors inside `model.where(...)` / `sql(t).where(...)` callbacks.
 *
 * Every operator's runtime impl (`../v3/operators-v3.ts`) encrypts the
 * user-supplied argument(s) at lowering time and stamps the column's
 * `(table, column)` routing context, then lowers to the canonical EQL
 * v3 function call. The comparand argument type is intentionally
 * permissive (`unknown`): the column `self` is the encrypted column;
 * the comparand is plaintext the operator encrypts on the user's
 * behalf.
 */
export type QueryOperationTypes<CT extends CodecTypesBase> =
  CT extends CodecTypesBase
    ? {
        // -------------------------------------------------------------
        // v3 surface (`eql*`, EQL-derived vocabulary — PR #655 review).
        // Every entry dispatches on a `cipherstash:v3-*` marker, which
        // only v3 codec entries carry. The comparand is `unknown`
        // because each operator spans every capable domain family
        // (bigint, date, numeric, …) and the runtime coerces + encrypts
        // per the column's castAs.
        // -------------------------------------------------------------
        readonly eqlEq: {
          readonly self: { readonly traits: V3EqualityMarker }
          readonly impl: (
            self: AnyExpressionLike,
            other: unknown,
          ) => PgBoolReturn
        }
        readonly eqlNeq: {
          readonly self: { readonly traits: V3EqualityMarker }
          readonly impl: (
            self: AnyExpressionLike,
            other: unknown,
          ) => PgBoolReturn
        }
        readonly eqlIn: {
          readonly self: { readonly traits: V3EqualityMarker }
          readonly impl: (
            self: AnyExpressionLike,
            values: readonly unknown[],
          ) => PgBoolReturn
        }
        readonly eqlNotIn: {
          readonly self: { readonly traits: V3EqualityMarker }
          readonly impl: (
            self: AnyExpressionLike,
            values: readonly unknown[],
          ) => PgBoolReturn
        }
        readonly eqlGt: {
          readonly self: { readonly traits: V3OrderAndRangeMarker }
          readonly impl: (
            self: AnyExpressionLike,
            other: unknown,
          ) => PgBoolReturn
        }
        readonly eqlGte: {
          readonly self: { readonly traits: V3OrderAndRangeMarker }
          readonly impl: (
            self: AnyExpressionLike,
            other: unknown,
          ) => PgBoolReturn
        }
        readonly eqlLt: {
          readonly self: { readonly traits: V3OrderAndRangeMarker }
          readonly impl: (
            self: AnyExpressionLike,
            other: unknown,
          ) => PgBoolReturn
        }
        readonly eqlLte: {
          readonly self: { readonly traits: V3OrderAndRangeMarker }
          readonly impl: (
            self: AnyExpressionLike,
            other: unknown,
          ) => PgBoolReturn
        }
        readonly eqlBetween: {
          readonly self: { readonly traits: V3OrderAndRangeMarker }
          readonly impl: (
            self: AnyExpressionLike,
            low: unknown,
            high: unknown,
          ) => PgBoolReturn
        }
        readonly eqlNotBetween: {
          readonly self: { readonly traits: V3OrderAndRangeMarker }
          readonly impl: (
            self: AnyExpressionLike,
            low: unknown,
            high: unknown,
          ) => PgBoolReturn
        }
        // Fuzzy free-text token match (`eql_v3.matches`) — NOT SQL
        // pattern matching; needles are guarded at lowering time
        // (wildcards, short needles). No negated form: the bloom test
        // may false-positive, so its negation would false-negative.
        readonly eqlMatch: {
          readonly self: { readonly traits: V3FreeTextSearchMarker }
          readonly impl: (
            self: AnyExpressionLike,
            needle: unknown,
          ) => PgBoolReturn
        }
        // v3-only: encrypted jsonb `@>` containment on `eql_v3_json_search`
        // columns.
        readonly eqlJsonContains: {
          readonly self: { readonly traits: V3SearchableJsonMarker }
          readonly impl: (
            self: AnyExpressionLike,
            needle: unknown,
          ) => PgBoolReturn
        }
        readonly eqlJsonPathEq: {
          readonly self: { readonly traits: V3SearchableJsonMarker }
          readonly impl: (
            self: AnyExpressionLike,
            path: string,
            value: string | number | boolean,
          ) => PgBoolReturn
        }
        readonly eqlJsonPathNeq: {
          readonly self: { readonly traits: V3SearchableJsonMarker }
          readonly impl: (
            self: AnyExpressionLike,
            path: string,
            value: string | number | boolean,
          ) => PgBoolReturn
        }
        readonly eqlJsonPathGt: {
          readonly self: { readonly traits: V3SearchableJsonMarker }
          readonly impl: (
            self: AnyExpressionLike,
            path: string,
            value: string | number,
          ) => PgBoolReturn
        }
        readonly eqlJsonPathGte: {
          readonly self: { readonly traits: V3SearchableJsonMarker }
          readonly impl: (
            self: AnyExpressionLike,
            path: string,
            value: string | number,
          ) => PgBoolReturn
        }
        readonly eqlJsonPathLt: {
          readonly self: { readonly traits: V3SearchableJsonMarker }
          readonly impl: (
            self: AnyExpressionLike,
            path: string,
            value: string | number,
          ) => PgBoolReturn
        }
        readonly eqlJsonPathLte: {
          readonly self: { readonly traits: V3SearchableJsonMarker }
          readonly impl: (
            self: AnyExpressionLike,
            path: string,
            value: string | number,
          ) => PgBoolReturn
        }
      }
    : never
