/**
 * Cipherstash v3 query-operations registry — the EQL v3 twin of the v2
 * `../execution/operators.ts`, lowering to the canonical v3 dialect
 * (`packages/stack-drizzle/src/v3/{operators,sql-dialect}.ts` is the
 * byte-for-byte reference):
 *
 *     eql_v3.eq(<col>, $n::eql_v3.query_<domain>)      -- equality (eqlEq)
 *     eql_v3.gt(<col>, $n::eql_v3.query_<domain>)      -- comparison (eqlGt)
 *     eql_v3.matches(<col>, $n::eql_v3.query_<domain>) -- bloom free-text (eqlMatch)
 *     <col> OPERATOR(public.@>) $n::eql_v3.query_json  -- JSON containment (eqlJsonContains)
 *     eql_v3.ord_term(<col>) / eql_v3.ord_term_ore(<col>) -- ordering (eqlAsc/eqlDesc)
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
 * ## v3 method names are EQL-derived (`eql*`), not `cipherstash*`
 *
 * The registered method names (`eqlEq`, `eqlGt`, `eqlMatch`, …) derive
 * from the `eql_v3.*` SQL functions they lower to, so the TS surface,
 * the SQL, and the EQL docs share one vocabulary (PR #655 review). The
 * `eql` prefix (rather than the bare `eq`/`gt`) is required: the
 * framework's native scope-field methods already claim `eq`, `neq`,
 * `gt`, `gte`, `lt`, `lte`, `in`, `notIn`, `like`, and those lower to
 * plain SQL comparisons — wrong for EQL ciphertexts. The v2 surface
 * keeps its historical `cipherstash*` names; the sets are disjoint, so
 * the v2 and v3 descriptors no longer share any registry key (the
 * never-co-registered stance of decision 1b still holds — a client is
 * v2 or v3 by construction, pinned in
 * `test/v3/operator-gating-v3.test.ts`). This module imports NO v2
 * codec/wire code — only the version-neutral envelope classes and the
 * shared trait constants.
 */

import {
  jsonPathOf,
  matchNeedleError,
  parseSelectorSegments,
  unsupportedLeafReason,
} from '@cipherstash/stack/adapter-kit'
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
  type EncryptedEnvelopeBase,
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
import {
  EncryptionOperatorError,
  markV3QueryTerm,
  type V3QueryTermType,
} from './query-term'

// The query-term seam (mark/read + the shared operator error) lives in
// `./query-term` so the bulk-encrypt middleware and the v3 SDK adapter
// can consume it without importing this module's operator registry.
// Re-exported here so the operator surface keeps its original shape.
export {
  EncryptionOperatorError,
  markV3QueryTerm,
  type V3QueryTermType,
  v3QueryTermTypeOf,
} from './query-term'

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
 * a template is built) and `eql_v3_json_search` maps to the irregular
 * `eql_v3.query_json`, cast explicitly on the JSON path.
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
        'reach the operator through the ORM model-accessor (e.g. `model.users.where((u) => u.email.eqlEq(...))`).',
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
 * (`eqlIn` / `eqlNotIn`): one query-term
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
 * Normalise and guard a free-text search needle BEFORE it is encrypted
 * (string needles only — envelope and non-string operands fall through
 * to `coerceV3`, which owns their diagnostics):
 *
 *   1. SQL wildcards: leading/trailing `%` are stripped (an
 *      `ilike`-shaped habit like `'%foo%'` still means "rows containing
 *      foo" under token matching), while an interior `%` or any `_`
 *      throws — the bloom tokenizer would treat them as ORDINARY
 *      CHARACTERS and silently match nothing. Mirrors
 *      stack-supabase's `likeNeedle`.
 *   2. Short needles: a needle below the match index's tokenizer
 *      length blooms to nothing and can match EVERY row; the shared
 *      `matchNeedleError` guard (adapter-kit — same check as the
 *      Drizzle and Supabase v3 surfaces) rejects it with the reason.
 */
function normalizeMatchNeedle(
  ctx: ColumnContext,
  value: unknown,
  method: string,
): unknown {
  if (typeof value !== 'string') return value
  const needle = value.replace(/^%+/, '').replace(/%+$/, '')
  if (needle.includes('%') || value.includes('_')) {
    throw operatorError(
      ctx,
      method,
      `cipherstash ${method}: pattern ${JSON.stringify(value)} on column "${ctx.columnName ?? 'unknown'}" has wildcards fuzzy free-text matching cannot honor (an interior "%" or any "_"). Pass a literal search term.`,
    )
  }
  const match = ctx.meta.indexes.match
  if (match !== undefined) {
    const reason = matchNeedleError(
      needle,
      // Narrowing assertion: `meta.indexes` is the widened
      // `Record<string, unknown>` snapshot of the column's `build()`
      // output; the `match` slot IS the match-index opts the shared
      // guard reads (same source the Drizzle adapter passes through).
      match as Parameters<typeof matchNeedleError>[1],
    )
    if (reason !== undefined) {
      throw operatorError(
        ctx,
        method,
        `Operator "${method}" cannot search column "${ctx.columnName ?? 'unknown'}": ${reason}`,
      )
    }
  }
  return needle
}

/**
 * Fuzzy free-text token match on a `text_search`/`text_match` column,
 * lowering to `eql_v3.matches` — NOT SQL pattern matching: matching is
 * case-insensitive, order- and multiplicity-insensitive, and one-sided
 * (may false-positive). The needle is normalised and guarded by
 * {@link normalizeMatchNeedle} before encryption.
 */
function matchOperator(): SqlOperationDescriptor {
  const method = 'eqlMatch'
  return {
    // See `fixedArityOperator` for the cast rationale.
    self: {
      traits: [
        CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
      ] as unknown as readonly CodecTrait[],
    },
    impl: (
      self: Expression<ScopeField>,
      needle: unknown,
    ): Expression<PgBoolReturn> => {
      const ctx = resolveContext(self, method)
      gate(ctx, FREE_TEXT_GATE.capability, FREE_TEXT_GATE.label, method)
      const cast = requireQueryCast(ctx, method)
      const guarded = normalizeMatchNeedle(ctx, needle, method)
      const argRef = asQueryTermParam(ctx, guarded, method, 'freeTextSearch')
      return buildOperation({
        method,
        args: [ctx.selfAst, argRef],
        returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
        lowering: {
          targetFamily: 'sql',
          strategy: 'function',
          template: `eql_v3.matches({{self}}, {{arg0}}::${cast})`,
        },
      })
    },
  }
}

/**
 * Exact encrypted-JSONB containment on an `eql_v3_json_search` (`ste_vec`)
 * column: genuine jsonb `@>`, no false positives. `eql_v3_json_search` has no
 * `eql_v3.matches` overload — containment is the `@>` operator, whose
 * `(eql_v3_json_search, eql_v3.query_json)` form takes a NARROWED query term
 * (searchableJson → no ciphertext) cast to the irregular
 * `eql_v3.query_json`. The explicit `OPERATOR(public.@>)` spelling
 * plus the cast disambiguate among the four `eql_v3_json_search @> ?` RHS
 * overloads ("operator is not unique", 42725).
 *
 * This mirrors the Drizzle reference's `contains` under the v3 `eql*`
 * vocabulary. A containedBy direction is exposed by neither adapter.
 */
function jsonContainsOperator(): SqlOperationDescriptor {
  const method = 'eqlJsonContains'
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
          template: '{{self}} OPERATOR(public.@>) {{arg0}}::eql_v3.query_json',
        },
      })
    },
  }
}

type JsonSelectorOp = 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte'

/**
 * Compare a scalar value at a JSONPath in an encrypted JSON document.
 *
 * Equality is value-selector containment, which is exact and can use the
 * document's functional GIN index. Ordering hashes the path separately and
 * compares the extracted entry with a ciphertext-free string/number ordering
 * term. The two query operands deliberately take different query routes.
 */
function jsonSelectorOperator(
  method: string,
  op: JsonSelectorOp,
): SqlOperationDescriptor {
  return {
    self: {
      traits: [
        CIPHERSTASH_TRAIT_SEARCHABLE_JSON,
      ] as unknown as readonly CodecTrait[],
    },
    impl: (
      self: Expression<ScopeField>,
      path: unknown,
      value: unknown,
    ): Expression<PgBoolReturn> => {
      const ctx = resolveContext(self, method)
      gate(ctx, JSON_GATE.capability, JSON_GATE.label, method)
      if (typeof path !== 'string') {
        throw operatorError(
          ctx,
          method,
          `cipherstash ${method}: expected a JSONPath string, got ${path === null ? 'null' : typeof path}.`,
        )
      }

      let canonicalPath: string
      try {
        canonicalPath = jsonPathOf(parseSelectorSegments(path))
      } catch (error) {
        throw operatorError(
          ctx,
          method,
          `cipherstash ${method}: ${error instanceof Error ? error.message : String(error)}`,
        )
      }

      const ordering = op !== 'eq' && op !== 'neq'
      const reason = unsupportedLeafReason(value, ordering)
      if (reason !== null) {
        throw operatorError(ctx, method, `cipherstash ${method}: ${reason}`)
      }

      if (!ordering) {
        const needle = asQueryTermParam(
          ctx,
          { path: canonicalPath, value },
          method,
          'steVecValueSelector',
        )
        const contains =
          '{{self}} OPERATOR(public.@>) {{arg0}}::eql_v3.query_json'
        return buildOperation({
          method,
          args: [ctx.selfAst, needle],
          returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
          lowering: {
            targetFamily: 'sql',
            strategy: 'function',
            template:
              op === 'eq'
                ? contains
                : `({{self}} IS NULL OR NOT (${contains}))`,
          },
        })
      }

      const selector = asQueryTermParam(
        ctx,
        canonicalPath,
        method,
        'steVecSelector',
      )
      const term = asQueryTermParam(ctx, value, method, 'steVecTerm')
      const queryCast =
        typeof value === 'string'
          ? 'eql_v3.query_text_ord'
          : 'eql_v3.query_double_ord'
      return buildOperation({
        method,
        args: [ctx.selfAst, selector, term],
        returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
        lowering: {
          targetFamily: 'sql',
          strategy: 'function',
          template: `eql_v3.${op}(eql_v3.jsonb_path_query_first({{self}}, {{arg0}}::text), {{arg1}}::${queryCast})`,
        },
      })
    },
  }
}

/**
 * Cipherstash's v3 query-operations contributions. Wired into the v3
 * runtime descriptor (Task 7's `createCipherstashV3RuntimeDescriptor`)
 * — and ONLY that descriptor (decision 1b: a client is v2 or v3, never
 * both; pinned in `test/v3/operator-gating-v3.test.ts`).
 *
 * Operator → trait → lowering:
 *
 *   - `eqlEq` / `eqlNeq` / `eqlIn` / `eqlNotIn`
 *     (`cipherstash:equality`) →
 *     `eql_v3.eq` / `eql_v3.neq` / OR-of-eq
 *   - `eqlGt` / `eqlGte` / `eqlLt` / `eqlLte` / `eqlBetween` /
 *     `eqlNotBetween` (`cipherstash:order-and-range`) →
 *     `eql_v3.gt`/`gte`/`lt`/`lte`, range as a self-parenthesised
 *     `(gte AND lte)` conjunction
 *   - `eqlMatch` (`cipherstash:free-text-search`) → `eql_v3.matches`
 *     — a bloom-filter TOKEN MATCH (order/multiplicity-insensitive,
 *     one-sided: may false-positive), NOT SQL pattern matching. Guarded
 *     up front: needles the column's match index cannot answer are
 *     rejected (`matchNeedleError`), and SQL wildcards are normalised
 *     away or rejected (see {@link matchOperator}).
 *   - `eqlJsonContains` (`cipherstash:searchable-json`) →
 *     exact jsonb containment via `OPERATOR(public.@>)`.
 *   - `eqlJsonPathEq/Neq/Gt/Gte/Lt/Lte`
 *     (`cipherstash:searchable-json`) → exact value-selector containment for
 *     equality, or selector extraction plus a ciphertext-free scalar query
 *     term for ordering.
 *
 * Every operand renders as `$n::eql_v3.query_<domain>` (irregularly
 * `::eql_v3.query_json` for JSON), matching the stack-drizzle v3
 * dialect byte-for-byte.
 */
export function cipherstashV3QueryOperations(): SqlOperationDescriptors {
  return {
    eqlEq: fixedArityOperator(
      'eqlEq',
      CIPHERSTASH_TRAIT_EQUALITY,
      1,
      EQUALITY_GATE,
      'equality',
      (cast) => `eql_v3.eq({{self}}, {{arg0}}::${cast})`,
    ),
    eqlNeq: fixedArityOperator(
      'eqlNeq',
      CIPHERSTASH_TRAIT_EQUALITY,
      1,
      EQUALITY_GATE,
      'equality',
      (cast) => `eql_v3.neq({{self}}, {{arg0}}::${cast})`,
    ),
    eqlIn: membershipOperator('eqlIn', false),
    eqlNotIn: membershipOperator('eqlNotIn', true),
    eqlGt: fixedArityOperator(
      'eqlGt',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      1,
      ORDERING_GATE,
      'orderAndRange',
      (cast) => `eql_v3.gt({{self}}, {{arg0}}::${cast})`,
    ),
    eqlGte: fixedArityOperator(
      'eqlGte',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      1,
      ORDERING_GATE,
      'orderAndRange',
      (cast) => `eql_v3.gte({{self}}, {{arg0}}::${cast})`,
    ),
    eqlLt: fixedArityOperator(
      'eqlLt',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      1,
      ORDERING_GATE,
      'orderAndRange',
      (cast) => `eql_v3.lt({{self}}, {{arg0}}::${cast})`,
    ),
    eqlLte: fixedArityOperator(
      'eqlLte',
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
    eqlBetween: fixedArityOperator(
      'eqlBetween',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      2,
      ORDERING_GATE,
      'orderAndRange',
      (cast) =>
        `(eql_v3.gte({{self}}, {{arg0}}::${cast}) AND eql_v3.lte({{self}}, {{arg1}}::${cast}))`,
    ),
    eqlNotBetween: fixedArityOperator(
      'eqlNotBetween',
      CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
      2,
      ORDERING_GATE,
      'orderAndRange',
      (cast) =>
        `NOT (eql_v3.gte({{self}}, {{arg0}}::${cast}) AND eql_v3.lte({{self}}, {{arg1}}::${cast}))`,
    ),
    eqlMatch: matchOperator(),
    // NO negated match: `eql_v3.matches` is a bloom-filter test that
    // may FALSE-POSITIVE, so its negation FALSE-NEGATIVES — it would
    // silently drop rows that genuinely don't match. A trustworthy
    // negative free-text search needs a decrypt-and-post-filter path;
    // until one exists the operator must not be offered (PR #655
    // review; same removal as the Drizzle/Supabase v3 surfaces).
    eqlJsonContains: jsonContainsOperator(),
    eqlJsonPathEq: jsonSelectorOperator('eqlJsonPathEq', 'eq'),
    eqlJsonPathNeq: jsonSelectorOperator('eqlJsonPathNeq', 'neq'),
    eqlJsonPathGt: jsonSelectorOperator('eqlJsonPathGt', 'gt'),
    eqlJsonPathGte: jsonSelectorOperator('eqlJsonPathGte', 'gte'),
    eqlJsonPathLt: jsonSelectorOperator('eqlJsonPathLt', 'lt'),
    eqlJsonPathLte: jsonSelectorOperator('eqlJsonPathLte', 'lte'),
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
 * `eql` prefix keeps the export distinct from the v2 helper AND names
 * the vocabulary it belongs to (free-standing exports share one barrel
 * namespace). Unlike v2 (bare-column sort over `eql_v2_encrypted`'s
 * native operator family), v3 domains have no cross-row comparison
 * operators — sorting MUST extract the order term. Synchronous: no
 * operand, so no query term is minted.
 */
export function eqlAsc(col: Expression<ScopeField>): OrderByItem {
  return OrderByItem.asc(ordTermExpression(col, 'eqlAsc').buildAst())
}

/**
 * DESC sort over an order-capable v3 column. See {@link eqlAsc}.
 */
export function eqlDesc(col: Expression<ScopeField>): OrderByItem {
  return OrderByItem.desc(ordTermExpression(col, 'eqlDesc').buildAst())
}
