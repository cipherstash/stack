/**
 * Cipherstash v3 query-operations registry — the EQL v3 twin of the v2
 * `../execution/operators.ts`, lowering to the canonical v3 dialect
 * (`packages/stack-drizzle/src/v3/{operators,sql-dialect}.ts` is the
 * byte-for-byte reference):
 *
 *     eql_v3.eq(<col>, $n::eql_v3.query_<domain>)      -- equality
 *     eql_v3.gt(<col>, $n::eql_v3.query_<domain>)      -- comparison
 *     eql_v3.contains(<col>, $n::eql_v3.query_<domain>) -- bloom free-text
 *     <col> OPERATOR(public.@>) $n::eql_v3.query_jsonb  -- JSON containment
 *     eql_v3.ord_term(<col>) / eql_v3.ord_term_ore(<col>) -- ordering
 *
 * ## Operands are QUERY TERMS, not storage envelopes
 *
 * Unlike v2 (where a WHERE operand is storage-encrypted by the
 * bulk-encrypt middleware and compared as a full `eql_v2_encrypted`
 * value), a v3 operand is a CIPHERTEXT-FREE query term minted by the
 * stack client's `encryptQuery`, cast to the column domain's
 * `eql_v3.query_<domain>` type. The cast is load-bearing: it reaches
 * the bundle's `(domain, query_<domain>)` overloads — the
 * storage-domain overload's CHECK demands the ciphertext `c` a query
 * term deliberately omits.
 *
 * At lowering time the operator therefore:
 *
 *   1. wraps the plaintext in the per-castAs `Encrypted*` envelope and
 *      stamps the column's `(table, column)` routing key (same
 *      write-once contract as v2 — SELECT envelopes must arrive at the
 *      middleware already routing-keyed);
 *   2. marks the envelope as a QUERY TERM with its `queryType`
 *      (`markV3QueryTerm` / `v3QueryTermTypeOf`) — the seam Task 7's
 *      SDK adapter consumes to route the operand through
 *      `encryptQuery({ queryType })` instead of the storage
 *      `bulkEncrypt` path;
 *   3. binds the envelope as a `pg/text@1` `ParamRef`. Deliberately NOT
 *      the column's own v3 codec: the Postgres renderer emits
 *      `$N::<nativeType>` for any codec-bound param, and the column
 *      codec's nativeType is the STORAGE domain (`public.eql_v3_*`) —
 *      whose CHECK a query term fails. `pg/text@1` renders a bare `$N`
 *      (text is planner-inferrable), the template supplies the
 *      `::eql_v3.query_<domain>` cast, and the driver value at execute
 *      time is the query term's JSONB text — a string, so the codec is
 *      truthful. The `pg/text@1` codec id also keeps these params
 *      OUTSIDE the storage bulk-encrypt middleware's jurisdiction
 *      (it matches on the v3 codec-id set), which is exactly right:
 *      query terms must never be storage-encrypted.
 *
 * ## Capability gating
 *
 * Trait dispatch (`cipherstash:*` traits on the codec descriptors)
 * decides which METHODS are visible on a column; the per-domain gate
 * here decides whether the CONCRETE domain can answer the call, and
 * throws {@link EncryptionOperatorError} naming the column, domain,
 * operator, and missing capability. Both layers are needed: traits are
 * derivation-time metadata, while a caller can reach a descriptor's
 * `impl` through a custom builder with any column expression.
 *
 * ## v2/v3 method-name identity (decision 1b)
 *
 * The registered method names (`cipherstashEq`, `cipherstashGt`, …)
 * are IDENTICAL to the v2 set — safe because the v2 and v3 runtime
 * descriptors are separate entry points that are never co-registered
 * (the flat `OperationRegistry` would throw on the shared names;
 * pinned in `test/v3/operator-gating-v3.test.ts`). This module imports
 * NO v2 codec/wire code — only the version-neutral envelope classes
 * and the shared trait constants.
 */

import type { QueryTypeName } from '@cipherstash/stack/types'
import type { CodecTrait } from '@prisma-next/framework-components/codec'
import type {
  SqlOperationDescriptor,
  SqlOperationDescriptors,
} from '@prisma-next/sql-operations'
import {
  type AnyExpression,
  type CodecRef,
  type ColumnRef,
  OrderByItem,
  ParamRef,
} from '@prisma-next/sql-relational-core/ast'
import {
  buildOperation,
  codecOf,
  type Expression,
  type ScopeField,
  toExpr,
} from '@prisma-next/sql-relational-core/expression'
import {
  EncryptedEnvelopeBase,
  setHandleRoutingKey,
} from '../execution/envelope-base'
import { EncryptedBigInt } from '../execution/envelope-bigint'
import { EncryptedBoolean } from '../execution/envelope-boolean'
import { EncryptedDate } from '../execution/envelope-date'
import { EncryptedJson } from '../execution/envelope-json'
import { EncryptedString } from '../execution/envelope-string'
import {
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
  CIPHERSTASH_TRAIT_SEARCHABLE_JSON,
} from '../extension-metadata/constants-v3'
import { V3_DOMAIN_META_BY_CODEC_ID, type V3DomainMeta } from './catalog'
import { EncryptedNumber } from './envelope-number'

/**
 * Codec ID of the framework's Postgres boolean codec — referenced as a
 * string so cipherstash does not pick up a peer-dep on the target
 * package just to identify a return-codec id (same pattern as v2).
 */
const PG_BOOL_CODEC_ID = 'pg/bool@1' as const

/**
 * Codec bound to every query-term `ParamRef` — see the module doc
 * ("Operands are QUERY TERMS") for why this is `pg/text@1` and not the
 * column's own v3 codec.
 */
const QUERY_TERM_PARAM_CODEC: CodecRef = { codecId: 'pg/text@1' }

type PgBoolReturn = {
  readonly codecId: typeof PG_BOOL_CODEC_ID
  readonly nullable: false
}

/**
 * A dedicated error for v3 operator gating, operand-coercion, and
 * misuse failures, carrying the offending column/table/operator for
 * diagnostics.
 *
 * INTENTIONAL FORK of `@cipherstash/stack-drizzle`'s error of the same
 * name (same shape, same rationale): sharing it would couple two
 * independently-versioned public packages. v3-owned — the v2 operator
 * surface keeps throwing plain `TypeError`s.
 */
export class EncryptionOperatorError extends Error {
  constructor(
    message: string,
    public readonly context?: {
      columnName?: string
      tableName?: string
      operator?: string
    },
  ) {
    super(message)
    this.name = 'EncryptionOperatorError'
  }
}

/**
 * The query-term flavours a v3 operator can mint — the subset of the
 * stack's `QueryTypeName` union that maps 1:1 onto the four
 * capability families (`steVecSelector`/`steVecTerm` are subsumed by
 * `searchableJson`, which auto-infers).
 */
export type V3QueryTermType = Extract<
  QueryTypeName,
  'equality' | 'orderAndRange' | 'freeTextSearch' | 'searchableJson'
>

/**
 * Query-term marks, keyed by envelope identity. A WeakMap sidecar
 * rather than a handle slot so the version-neutral
 * `EncryptedEnvelopeHandle` (shared with v2, which has no query-term
 * concept) stays untouched.
 */
const V3_QUERY_TERM_TYPES = new WeakMap<
  EncryptedEnvelopeBase<unknown>,
  V3QueryTermType
>()

/**
 * Mark an envelope as a v3 QUERY TERM of the given flavour. Stamped by
 * every operator at lowering time; consumed by the v3 SDK boundary
 * (Task 7), which must encrypt marked envelopes via
 * `encryptQuery({ queryType })` — a ciphertext-free term — instead of
 * the storage `bulkEncrypt` path. Write-once-wins with a conflict
 * check, mirroring `setHandleRoutingKey`: one envelope instance feeds
 * one query flavour.
 */
export function markV3QueryTerm(
  envelope: EncryptedEnvelopeBase<unknown>,
  queryType: V3QueryTermType,
): void {
  const existing = V3_QUERY_TERM_TYPES.get(envelope)
  if (existing !== undefined && existing !== queryType) {
    throw new EncryptionOperatorError(
      `cipherstash v3 operator: envelope is already marked as a "${existing}" query term, refusing to remark as "${queryType}". Construct a fresh envelope per operator call.`,
    )
  }
  V3_QUERY_TERM_TYPES.set(envelope, queryType)
}

/**
 * Read an envelope's query-term mark. `undefined` means the envelope
 * is a storage value (write path), not a query term.
 */
export function v3QueryTermTypeOf(
  envelope: unknown,
): V3QueryTermType | undefined {
  return envelope instanceof EncryptedEnvelopeBase
    ? V3_QUERY_TERM_TYPES.get(envelope)
    : undefined
}

/** Per-call column context resolved from the `self` expression. */
interface ColumnContext {
  readonly meta: V3DomainMeta
  readonly selfCodec: CodecRef
  readonly selfAst: AnyExpression
  readonly columnName: string | undefined
  readonly tableName: string | undefined
}

/**
 * The `eql_v3.query_<domain>` cast for a column's storage domain —
 * `public.eql_v3_text_search` → `eql_v3.query_text_search`. Uniform
 * across the queryable column domains (`_eq`, `_ord`, `_ord_ore`,
 * `_match`, `_search`); the irregular cases are handled elsewhere:
 * storage-only domains have no query type (they are gated out before
 * a template is built) and `eql_v3_json` maps to the irregular
 * `eql_v3.query_jsonb`, cast explicitly on the JSON path.
 */
function queryCastForMeta(meta: V3DomainMeta): string | null {
  const prefix = 'eql_v3_'
  if (!meta.bareDomain.startsWith(prefix)) return null
  const suffix = meta.bareDomain.slice(prefix.length)
  if (!/_(eq|ord|ord_ore|match|search)$/.test(suffix)) {
    return null
  }
  return `eql_v3.query_${suffix}`
}

function requireSelfCodec(
  self: Expression<ScopeField>,
  method: string,
): CodecRef {
  const codec = codecOf(self)
  if (codec === undefined) {
    throw new EncryptionOperatorError(
      `cipherstash ${method}: self expression is missing a CodecRef. ` +
        'Cipherstash predicate operators require a column-bound self argument; ' +
        'reach the operator through the ORM model-accessor (e.g. `model.users.where((u) => u.email.cipherstashEq(...))`).',
      { operator: method },
    )
  }
  return codec
}

/**
 * Find the column reference inside a `self` expression so the operator
 * can stamp routing keys and name the column in diagnostics. Same
 * resolution ladder as v2: a direct `ColumnRef`, then the
 * `baseColumnRef()` walk, then `undefined` (literal self — routing
 * stamping is skipped and the middleware surfaces the missing-routing
 * diagnostic at execute time).
 */
function extractColumnRef(selfAst: AnyExpression): ColumnRef | undefined {
  if (selfAst.kind === 'column-ref') {
    return selfAst
  }
  try {
    return selfAst.baseColumnRef()
  } catch {
    return undefined
  }
}

function resolveContext(
  self: Expression<ScopeField>,
  method: string,
): ColumnContext {
  const selfCodec = requireSelfCodec(self, method)
  const selfAst = toExpr(self, selfCodec)
  const columnRef = extractColumnRef(selfAst)
  const meta = V3_DOMAIN_META_BY_CODEC_ID.get(selfCodec.codecId)
  if (!meta) {
    throw new EncryptionOperatorError(
      `cipherstash ${method}: column codec id "${selfCodec.codecId}" is not a public.eql_v3_* v3 domain. ` +
        'v2 cipherstash columns are the wrong entry point for the v3 operator surface — ' +
        'a client is v2 or v3, never both (decision 1b).',
      {
        operator: method,
        ...(columnRef ? { columnName: columnRef.column } : {}),
        ...(columnRef ? { tableName: columnRef.table } : {}),
      },
    )
  }
  return {
    meta,
    selfCodec,
    selfAst,
    columnName: columnRef?.column,
    tableName: columnRef?.table,
  }
}

/**
 * Gate an operator on the concrete domain's query capabilities. The
 * capability set is intrinsic to the domain (catalog-derived — the
 * same source that drives the codec descriptors' traits and the
 * authoring `typeParams.capabilities` block), so gating here can never
 * disagree with what the column advertises.
 */
function gate(
  ctx: ColumnContext,
  capability: keyof V3DomainMeta['capabilities'],
  label: string,
  method: string,
): void {
  if (!ctx.meta.capabilities[capability]) {
    throw new EncryptionOperatorError(
      `Operator "${method}" requires ${label} on column "${ctx.columnName ?? 'unknown'}" (domain ${ctx.meta.nativeType} does not support it).`,
      {
        columnName: ctx.columnName ?? 'unknown',
        tableName: ctx.tableName ?? 'unknown',
        operator: method,
      },
    )
  }
}

function operatorError(
  ctx: ColumnContext,
  method: string,
  message: string,
): EncryptionOperatorError {
  return new EncryptionOperatorError(message, {
    columnName: ctx.columnName ?? 'unknown',
    tableName: ctx.tableName ?? 'unknown',
    operator: method,
  })
}

function requireNonNullOperand(
  ctx: ColumnContext,
  value: unknown,
  method: string,
): void {
  if (value == null) {
    throw operatorError(
      ctx,
      method,
      `cipherstash ${method}: cannot encrypt a null operand for column "${ctx.columnName ?? 'unknown'}". Use isNull() or isNotNull() for NULL checks.`,
    )
  }
}

/**
 * Coerce a user-supplied value into the envelope subclass matching the
 * domain's `castAs` (raw plaintext or a pre-built envelope). Total
 * over `V3CastAs`; the diagnostic names the expected plaintext type.
 */
function coerceV3(
  ctx: ColumnContext,
  value: unknown,
  method: string,
): EncryptedEnvelopeBase<unknown> {
  requireNonNullOperand(ctx, value, method)
  switch (ctx.meta.castAs) {
    case 'string':
      if (value instanceof EncryptedString) return value
      if (typeof value === 'string') return EncryptedString.from(value)
      break
    case 'number':
      if (value instanceof EncryptedNumber) return value
      if (typeof value === 'number') return EncryptedNumber.from(value)
      break
    case 'bigint':
      if (value instanceof EncryptedBigInt) return value
      if (typeof value === 'bigint') return EncryptedBigInt.from(value)
      break
    case 'date':
    case 'timestamp':
      if (value instanceof EncryptedDate) return value
      if (value instanceof Date) return EncryptedDate.from(value)
      break
    case 'boolean':
      if (value instanceof EncryptedBoolean) return value
      if (typeof value === 'boolean') return EncryptedBoolean.from(value)
      break
    case 'json':
      if (value instanceof EncryptedJson) return value
      return EncryptedJson.from(value)
  }
  const got =
    value === null ? 'null' : value instanceof Date ? 'Date' : typeof value
  throw operatorError(
    ctx,
    method,
    `cipherstash ${method}: value is not assignable to castAs "${ctx.meta.castAs}" for domain ${ctx.meta.nativeType}, got ${got}.`,
  )
}

/**
 * Wrap a user value as a query-term `ParamRef`: coerce to the
 * per-castAs envelope, stamp the `(table, column)` routing key
 * (write-once-wins), mark the query-term flavour for the SDK boundary,
 * and bind under the bare-rendering `pg/text@1` codec (the template
 * supplies the `::eql_v3.query_<domain>` cast).
 */
function asQueryTermParam(
  ctx: ColumnContext,
  value: unknown,
  method: string,
  queryType: V3QueryTermType,
): ParamRef {
  const envelope = coerceV3(ctx, value, method)
  if (ctx.tableName !== undefined && ctx.columnName !== undefined) {
    setHandleRoutingKey(envelope, ctx.tableName, ctx.columnName)
  }
  markV3QueryTerm(envelope, queryType)
  return ParamRef.of(envelope, { codec: QUERY_TERM_PARAM_CODEC })
}

/**
 * The `::eql_v3.query_<domain>` cast for a gated context. The gate ran
 * first, so a missing query type here means the catalog and the gate
 * disagree — an internal invariant violation, not a user error.
 */
function requireQueryCast(ctx: ColumnContext, method: string): string {
  const cast = queryCastForMeta(ctx.meta)
  if (cast === null) {
    throw operatorError(
      ctx,
      method,
      `cipherstash ${method}: domain ${ctx.meta.nativeType} passed its capability gate but has no eql_v3.query_* operand type. This is a bug in @cipherstash/prisma-next — please report it.`,
    )
  }
  return cast
}

interface GateSpec {
  readonly capability: keyof V3DomainMeta['capabilities']
  readonly label: string
}

const EQUALITY_GATE: GateSpec = { capability: 'equality', label: 'equality' }
const ORDERING_GATE: GateSpec = {
  capability: 'orderAndRange',
  label: 'order/range',
}
const FREE_TEXT_GATE: GateSpec = {
  capability: 'freeTextSearch',
  label: 'free-text search',
}
const JSON_GATE: GateSpec = {
  capability: 'searchableJson',
  label: 'JSON containment',
}

/**
 * Build a fixed-arity v3 predicate operator dispatched via a
 * cipherstash-namespaced trait. The lowering template is built PER
 * CALL from the concrete domain (the `::eql_v3.query_<domain>` cast is
 * domain-dependent), via {@link buildTemplate} over the resolved cast.
 */
function fixedArityOperator(
  method: string,
  trait: string,
  arity: number,
  gateSpec: GateSpec,
  queryType: V3QueryTermType,
  buildTemplate: (cast: string) => string,
): SqlOperationDescriptor {
  return {
    // Cipherstash trait identifiers (`cipherstash:equality`, …) live
    // outside the framework's closed `CodecTrait` union; the runtime
    // dispatcher widens to `readonly string[]` before matching. Same
    // pattern (and full rationale) as the v2 operators and
    // `codec-runtime-v3.ts`; AGENTS.md requires this rationale comment
    // alongside any `as unknown as` cast.
    self: { traits: [trait] as unknown as readonly CodecTrait[] },
    impl: (
      self: Expression<ScopeField>,
      ...userArgs: unknown[]
    ): Expression<PgBoolReturn> => {
      if (userArgs.length !== arity) {
        throw new EncryptionOperatorError(
          `cipherstash ${method}: expected ${arity} argument${arity === 1 ? '' : 's'}, got ${userArgs.length}.`,
          { operator: method },
        )
      }
      const ctx = resolveContext(self, method)
      gate(ctx, gateSpec.capability, gateSpec.label, method)
      const cast = requireQueryCast(ctx, method)
      const argRefs = userArgs.map((value) =>
        asQueryTermParam(ctx, value, method, queryType),
      )
      return buildOperation({
        method,
        args: [ctx.selfAst, ...argRefs],
        returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
        lowering: {
          targetFamily: 'sql',
          strategy: 'function',
          template: buildTemplate(cast),
        },
      })
    },
  }
}

/**
 * Build a variable-arity v3 membership operator
 * (`cipherstashInArray` / `cipherstashNotInArray`): one query-term
 * param per array element, template built per call from the array
 * length AND the domain's query cast. Empty arrays are rejected — an
 * OR-of-zero fragments has no well-defined lowering, and a silent
 * `FALSE` rewrite would mask the caller's likely intent.
 */
function membershipOperator(
  method: string,
  negate: boolean,
): SqlOperationDescriptor {
  return {
    // See `fixedArityOperator` for the cast rationale.
    self: {
      traits: [CIPHERSTASH_TRAIT_EQUALITY] as unknown as readonly CodecTrait[],
    },
    impl: (
      self: Expression<ScopeField>,
      values: unknown,
    ): Expression<PgBoolReturn> => {
      if (!Array.isArray(values)) {
        throw new EncryptionOperatorError(
          `cipherstash ${method}: expected an array argument, got ${
            values === null ? 'null' : typeof values
          }.`,
          { operator: method },
        )
      }
      if (values.length === 0) {
        throw new EncryptionOperatorError(
          `cipherstash ${method}: empty array is not supported. ` +
            'An empty membership check has no well-defined SQL lowering — use ' +
            '`WHERE FALSE` directly if you want to match no rows.',
          { operator: method },
        )
      }
      const ctx = resolveContext(self, method)
      gate(ctx, EQUALITY_GATE.capability, EQUALITY_GATE.label, method)
      const cast = requireQueryCast(ctx, method)
      const argRefs = values.map((value) =>
        asQueryTermParam(ctx, value, method, 'equality'),
      )
      const terms = values.map(
        (_, i) => `eql_v3.eq({{self}}, {{arg${i}}}::${cast})`,
      )
      const disjunction = `(${terms.join(' OR ')})`
      return buildOperation({
        method,
        args: [ctx.selfAst, ...argRefs],
        returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
        lowering: {
          targetFamily: 'sql',
          strategy: 'function',
          template: negate ? `NOT ${disjunction}` : disjunction,
        },
      })
    },
  }
}

/**
 * Exact encrypted-JSONB containment on an `eql_v3_json` (`ste_vec`)
 * column: genuine jsonb `@>`, no false positives. `eql_v3_json` has no
 * `eql_v3.contains` overload — containment is the `@>` operator, whose
 * `(eql_v3_json, eql_v3.query_jsonb)` form takes a NARROWED query term
 * (searchableJson → no ciphertext) cast to the irregular
 * `eql_v3.query_jsonb`. The explicit `OPERATOR(public.@>)` spelling
 * plus the cast disambiguate among the four `eql_v3_json @> ?` RHS
 * overloads ("operator is not unique", 42725).
 *
 * This mirrors the drizzle reference's `contains` under the v2 set's
 * `cipherstashJson*` naming convention. The reference exposes neither
 * a containedBy direction nor selector querying, so neither is
 * registered here.
 */
function jsonContainsOperator(): SqlOperationDescriptor {
  const method = 'cipherstashJsonContains'
  return {
    // See `fixedArityOperator` for the cast rationale.
    self: {
      traits: [
        CIPHERSTASH_TRAIT_SEARCHABLE_JSON,
      ] as unknown as readonly CodecTrait[],
    },
    impl: (
      self: Expression<ScopeField>,
      needle: unknown,
    ): Expression<PgBoolReturn> => {
      const ctx = resolveContext(self, method)
      gate(ctx, JSON_GATE.capability, JSON_GATE.label, method)
      requireNonNullOperand(ctx, needle, method)
      // Reject the empty-object needle: `doc @> '{}'` holds for EVERY
      // document (jsonb `{} ⊆ anything`), so it would silently return
      // the whole table. An accidental empty filter is a bug, not a
      // match-all request (same guard as the drizzle reference).
      if (
        needle !== null &&
        typeof needle === 'object' &&
        !Array.isArray(needle) &&
        Object.keys(needle).length === 0
      ) {
        throw operatorError(
          ctx,
          method,
          `cipherstash ${method}: an empty object needle on column "${ctx.columnName ?? 'unknown'}" matches every row. Pass a non-empty sub-object, or omit the predicate to select all rows.`,
        )
      }
      const argRef = asQueryTermParam(ctx, needle, method, 'searchableJson')
      return buildOperation({
        method,
        args: [ctx.selfAst, argRef],
        returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
        lowering: {
          targetFamily: 'sql',
          strategy: 'function',
          template: '{{self}} OPERATOR(public.@>) {{arg0}}::eql_v3.query_jsonb',
        },
      })
    },
  }
}

/**
 * Cipherstash's v3 query-operations contributions. Wired into the v3
 * runtime descriptor (Task 7's `createCipherstashV3RuntimeDescriptor`)
 * — and ONLY that descriptor: the method names are shared with the v2
 * set, and the flat `OperationRegistry` rejects co-registration
 * (decision 1b; pinned in `test/v3/operator-gating-v3.test.ts`).
 *
 * Operator → trait → lowering:
 *
 *   - `cipherstashEq` / `cipherstashNe` / `cipherstashInArray` /
 *     `cipherstashNotInArray` (`cipherstash:equality`) →
 *     `eql_v3.eq` / `eql_v3.neq` / OR-of-eq
 *   - `cipherstashGt` / `Gte` / `Lt` / `Lte` / `Between` / `NotBetween`
 *     (`cipherstash:order-and-range`) → `eql_v3.gt`/`gte`/`lt`/`lte`,
 *     range as a self-parenthesised `(gte AND lte)` conjunction
 *   - `cipherstashIlike` / `cipherstashNotIlike`
 *     (`cipherstash:free-text-search`) → `eql_v3.contains` — a
 *     bloom-filter TOKEN MATCH (order/multiplicity-insensitive,
 *     one-sided: may false-positive), NOT SQL ILIKE; the v2 method
 *     names are kept for surface continuity.
 *   - `cipherstashJsonContains` (`cipherstash:searchable-json`) →
 *     exact jsonb containment via `OPERATOR(public.@>)`.
 *
 * Every operand renders as `$n::eql_v3.query_<domain>` (irregularly
 * `::eql_v3.query_jsonb` for JSON), matching the stack-drizzle v3
 * dialect byte-for-byte.
 */
export function cipherstashV3QueryOperations(): SqlOperationDescriptors {
  return {
    cipherstashEq: fixedArityOperator(
      'cipherstashEq',
      CIPHERSTASH_TRAIT_EQUALITY,
      1,
      EQUALITY_GATE,
      'equality',
      (cast) => `eql_v3.eq({{self}}, {{arg0}}::${cast})`,
    ),
    cipherstashNe: fixedArityOperator(
      'cipherstashNe',
      CIPHERSTASH_TRAIT_EQUALITY,
      1,
      EQUALITY_GATE,
      'equality',
      (cast) => `eql_v3.neq({{self}}, {{arg0}}::${cast})`,
    ),
    cipherstashInArray: membershipOperator('cipherstashInArray', false),
    cipherstashNotInArray: membershipOperator('cipherstashNotInArray', true),
    cipherstashGt: fixedArityOperator(
      'cipherstashGt',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      1,
      ORDERING_GATE,
      'orderAndRange',
      (cast) => `eql_v3.gt({{self}}, {{arg0}}::${cast})`,
    ),
    cipherstashGte: fixedArityOperator(
      'cipherstashGte',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      1,
      ORDERING_GATE,
      'orderAndRange',
      (cast) => `eql_v3.gte({{self}}, {{arg0}}::${cast})`,
    ),
    cipherstashLt: fixedArityOperator(
      'cipherstashLt',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      1,
      ORDERING_GATE,
      'orderAndRange',
      (cast) => `eql_v3.lt({{self}}, {{arg0}}::${cast})`,
    ),
    cipherstashLte: fixedArityOperator(
      'cipherstashLte',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      1,
      ORDERING_GATE,
      'orderAndRange',
      (cast) => `eql_v3.lte({{self}}, {{arg0}}::${cast})`,
    ),
    // between's template is a SELF-CONTAINED PARENTHESISED conjunction.
    // The parens are load-bearing, not cosmetic: Postgres binds NOT
    // tighter than AND, so an unparenthesised `gte AND lte` under any
    // generic negation (a framework `not(between(...))`, an OR
    // composition, …) parses as `(NOT gte) AND lte` — rows BELOW the
    // lower bound instead of the range complement. Parenthesising here
    // makes every composition safe instead of relying on each caller.
    cipherstashBetween: fixedArityOperator(
      'cipherstashBetween',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      2,
      ORDERING_GATE,
      'orderAndRange',
      (cast) =>
        `(eql_v3.gte({{self}}, {{arg0}}::${cast}) AND eql_v3.lte({{self}}, {{arg1}}::${cast}))`,
    ),
    cipherstashNotBetween: fixedArityOperator(
      'cipherstashNotBetween',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      2,
      ORDERING_GATE,
      'orderAndRange',
      (cast) =>
        `NOT (eql_v3.gte({{self}}, {{arg0}}::${cast}) AND eql_v3.lte({{self}}, {{arg1}}::${cast}))`,
    ),
    // ilike/notIlike lower to eql_v3.contains — bloom-filter token
    // matching, NOT SQL ILIKE (may false-positive; carry this caveat
    // into user docs).
    cipherstashIlike: fixedArityOperator(
      'cipherstashIlike',
      CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
      1,
      FREE_TEXT_GATE,
      'freeTextSearch',
      (cast) => `eql_v3.contains({{self}}, {{arg0}}::${cast})`,
    ),
    cipherstashNotIlike: fixedArityOperator(
      'cipherstashNotIlike',
      CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
      1,
      FREE_TEXT_GATE,
      'freeTextSearch',
      (cast) => `NOT eql_v3.contains({{self}}, {{arg0}}::${cast})`,
    ),
    cipherstashJsonContains: jsonContainsOperator(),
  }
}

/**
 * Build the encrypted order-term extractor expression for a column:
 * `eql_v3.ord_term(col)` for OPE-backed `_ord` domains (and
 * `text_search`), `eql_v3.ord_term_ore(col)` for block-ORE `_ord_ore`
 * domains — eql-3.0.0 splits the extractor by term flavour, keyed off
 * the column's own index set (matching the drizzle reference's
 * `orderBy` dialect).
 *
 * The expression's declared return codec is the COLUMN's codec ref.
 * The extractor's real SQL type is an internal ordering term
 * (`eql_v3_internal.*`) that no codec models; the value is only ever
 * consumed positionally inside ORDER BY (never projected or bound), so
 * the return-type slot is type-level plumbing only.
 */
function ordTermExpression(
  col: Expression<ScopeField>,
  method: string,
): Expression<ScopeField> {
  const ctx = resolveContext(col, method)
  gate(ctx, ORDERING_GATE.capability, ORDERING_GATE.label, method)
  const fn = ctx.meta.indexes.ore ? 'ord_term_ore' : 'ord_term'
  return buildOperation({
    method,
    args: [ctx.selfAst],
    returns: { codecId: ctx.selfCodec.codecId, nullable: true },
    lowering: {
      targetFamily: 'sql',
      strategy: 'function',
      template: `eql_v3.${fn}({{self}})`,
    },
  })
}

/**
 * ASC sort over an order-capable v3 column, via the encrypted
 * order-term extractor: `ORDER BY eql_v3.ord_term(col) ASC` (or
 * `ord_term_ore` on a block-ORE domain).
 *
 * A free-standing helper, not a registered operator — same rationale
 * as the v2 `cipherstashAsc`: sort returns an `OrderByItem`, not the
 * boolean predicate the registry's where-binding pipeline expects. The
 * `V3` suffix keeps the export distinct from the v2 helper (unlike
 * registry method names, free-standing exports share one barrel
 * namespace). Unlike v2 (bare-column sort over `eql_v2_encrypted`'s
 * native operator family), v3 domains have no cross-row comparison
 * operators — sorting MUST extract the order term. Synchronous: no
 * operand, so no query term is minted.
 */
export function cipherstashV3Asc(col: Expression<ScopeField>): OrderByItem {
  return OrderByItem.asc(ordTermExpression(col, 'cipherstashV3Asc').buildAst())
}

/**
 * DESC sort over an order-capable v3 column. See {@link cipherstashV3Asc}.
 */
export function cipherstashV3Desc(col: Expression<ScopeField>): OrderByItem {
  return OrderByItem.desc(
    ordTermExpression(col, 'cipherstashV3Desc').buildAst(),
  )
}
