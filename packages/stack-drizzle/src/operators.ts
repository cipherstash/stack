import type { Result } from '@byteslice/result'
import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import {
  jsonPathOf,
  matchNeedleError,
  parseSelectorSegments,
  reconstructSelectorDocument,
  stripDomainSchema,
  unsupportedLeafReason,
} from '@cipherstash/stack/adapter-kit'
import type {
  AnyEncryptedV3Column,
  AnyV3Table,
} from '@cipherstash/stack/eql/v3'
import type { EncryptionError } from '@cipherstash/stack/errors'
import type { LockContext } from '@cipherstash/stack/identity'
import type { ColumnSchema } from '@cipherstash/stack/schema'
import type {
  EncryptedQueryResult,
  QueryTypeName,
} from '@cipherstash/stack/types'
import {
  and,
  asc,
  Column,
  desc,
  exists,
  is,
  isNotNull,
  isNull,
  not,
  notExists,
  or,
  type SQL,
  type SQLWrapper,
  sql,
} from 'drizzle-orm'
import type { PgTable } from 'drizzle-orm/pg-core'
import { getEqlV3Column } from './column.js'
import {
  extractEncryptionSchema,
  getDrizzleTableName,
} from './schema-extraction.js'
import { type ComparisonOp, type EqualityOp, v3Dialect } from './sql-dialect.js'

/**
 * The client capability this factory consumes: `encryptQuery`, in both its
 * single (`value, opts`) and batch (`terms[]`) forms. Declared structurally —
 * with maximally-permissive operands — so it is satisfied by the nominal
 * `EncryptionClient`, by the `TypedEncryptionClient` that `EncryptionV3` returns
 * (whatever its schema tuple), AND by a hand-rolled test double, none needing a
 * cast. Typing the parameter to the nominal `TypedEncryptionClient<S>` would
 * reject a client built for a narrower schema tuple (it accepts fewer tables than
 * `readonly AnyV3Table[]`); the structural surface sidesteps that variance.
 *
 * Every operand is a QUERY TERM, not a storage envelope: `encryptQuery` mints a
 * ciphertext-free term (no `c`) carrying all of the column's configured index
 * terms, which the operator layer casts to the column's `eql_v3.query_<domain>`
 * type. This reaches the bundle's `(domain, query_<domain>)` overloads and keeps
 * WHERE-clause payloads free of the ciphertext a query never needs (#622).
 *
 * `never` operands: the real client's `encryptQuery` is generic (`queryType` is
 * constrained to the column's own query types), which a concrete signature here
 * cannot match. `never` params keep the structural surface satisfiable by that
 * generic method AND by a test double; the call sites cast their real operands.
 */
type OperandEncryptionClient = {
  encryptQuery(
    value: never,
    opts: never,
  ): ChainableOperation<EncryptedQueryResult>
  encryptQuery(terms: never): ChainableOperation<EncryptedQueryResult[]>
}

// Path helpers now live in @cipherstash/stack/adapter-kit (shared with the
// Supabase adapter, #650); re-exported so existing imports keep working.
export { parseSelectorSegments, reconstructSelectorDocument }

/**
 * A dedicated error for v3 operator gating and operand-encryption failures,
 * carrying the offending column/table/operator for diagnostics.
 *
 * INTENTIONAL FORK: this mirrors the v2 adapter's `EncryptionOperatorError`
 * rather than sharing it. Unifying the two would couple `./drizzle` and
 * `./eql/v3/drizzle` — two independently-versioned public entry points — so the
 * duplication is deliberate, not an oversight.
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

interface ColumnContext {
  builder: AnyEncryptedV3Column
  table: AnyV3Table
  indexes: ColumnSchema['indexes']
  columnName: string
  tableName: string
  /** The `eql_v3.query_<domain>` type an operand for this column casts to, so
   * `encryptQuery`'s ciphertext-free term reaches the narrowed-query overloads.
   * `null` for storage-only columns (no query domain); those never encrypt an
   * operand — every operator gates on a query capability first. JSON columns
   * override this at the call site (`query_json`, an irregular name). */
  queryCast: string | null
}

/**
 * The `eql_v3.query_<domain>` cast for a column's storage domain — e.g.
 * `public.eql_v3_text_search` → `eql_v3.query_text_search`. Uniform across the
 * queryable column domains (`_eq`, `_ord`, `_ord_ore`, `_match`, `_search`); the
 * two irregular cases are handled elsewhere: storage-only domains
 * (`eql_v3_boolean`, the bare base types) have no query domain and return `null`
 * (they are never queried), and `eql_v3_json_search` maps to `query_json`, cast
 * explicitly on the JSON path.
 */
function queryCastForDomain(eqlType: string): string | null {
  const bare = stripDomainSchema(eqlType) // public.eql_v3_text_search → eql_v3_text_search
  const prefix = 'eql_v3_'
  if (!bare.startsWith(prefix)) return null
  const suffix = bare.slice(prefix.length)
  // No index suffix (bare storage-only domain like `boolean`, `text`) → no query
  // domain exists. These are gated out before any operand is encrypted. The
  // suffixes match the column factories in `@/eql/v3/columns` exactly: ope
  // ordering is the `_ord` domain (not `_ord_ope`) and text search is `_search`
  // (there is no `_search_ore` column), so those two never occur here.
  if (!/_(eq|ord|ord_ore|match|search)$/.test(suffix)) {
    return null
  }
  return `eql_v3.query_${suffix}`
}

export type EncryptionOperatorCallOpts = {
  lockContext?: LockContext
  audit?: AuditConfig
}

/**
 * An SDK encryption operation after its lock context has been applied: still
 * auditable and awaitable, but not re-lockable. `withLockContext` returns this,
 * not the full {@link ChainableOperation}, mirroring the real
 * `EncryptOperationWithLockContext`, which drops `withLockContext` (you cannot
 * lock-context twice). Modelling that is what lets the real client type satisfy
 * the structural surface with no cast.
 */
type AuditableOperation<T> = {
  audit(config: AuditConfig): AuditableOperation<T>
  then: PromiseLike<Result<T, EncryptionError>>['then']
}

/**
 * The subset of an SDK encryption operation this factory drives: the fluent
 * `withLockContext`/`audit` chain, and a `then` that resolves the operation's
 * `Result`. Generic over the resolved payload `T` so the single `encryptQuery`
 * carries an `EncryptedQueryResult` term and the batch form an
 * `EncryptedQueryResult[]`, rather than the `unknown` this erased to before.
 *
 * Structural, not the concrete `EncryptQueryOperation` class, because the client
 * is passed in and the factory must accept any implementation with this surface.
 */
type ChainableOperation<T> = {
  withLockContext(lockContext: LockContext): AuditableOperation<T>
  audit(config: AuditConfig): AuditableOperation<T>
  then: PromiseLike<Result<T, EncryptionError>>['then']
}

/**
 * Build v3-aware query operators (`eq`, `gte`, `matches`, `contains`, `asc`, …) bound to an
 * encryption `client`. Each comparison/containment operator AUTO-ENCRYPTS its
 * plaintext operand into an EQL v3 query term before handing it to Drizzle, so
 * callers pass plaintext and the emitted SQL compares encrypted values. Every
 * operator also gates on the target column's capabilities and throws
 * {@link EncryptionOperatorError} when the column can't answer the operator
 * (e.g. ordering a non-`ore` column).
 *
 * @param client - anything that can `encryptQuery` — the nominal
 *   `EncryptionClient` or the `TypedEncryptionClient` from `EncryptionV3` (no
 *   cast needed).
 * @param defaults - lock context / audit applied to every operand encryption
 *   unless a per-call override is supplied.
 *
 * @example
 * ```typescript
 * const ops = createEncryptionOperators(await EncryptionV3({ schemas: [users] }))
 * await db.select().from(users).where(await ops.eq(users.email, 'a@b.com'))
 * ```
 */
export function createEncryptionOperators(
  client: OperandEncryptionClient,
  defaults: EncryptionOperatorCallOpts = {},
) {
  const tableCache = new WeakMap<PgTable, AnyV3Table>()
  // Per-column context memo. `resolveContext` is value-independent, so caching
  // by column identity makes `inArray`/`notInArray` build the context (and its
  // deep-cloned match block) once for the whole list instead of once per value.
  const contextCache = new WeakMap<SQLWrapper, ColumnContext>()

  function drizzleTableOf(column: SQLWrapper): PgTable | undefined {
    return is(column, Column)
      ? (column.table as PgTable | undefined)
      : undefined
  }

  function resolveContext(column: SQLWrapper, operator: string): ColumnContext {
    const cached = contextCache.get(column)
    if (cached) return cached

    const columnName = is(column, Column) ? column.name : 'unknown'
    const builder = getEqlV3Column(columnName, column)
    if (!builder) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires an encrypted v3 column, but "${columnName}" is not one.`,
        { columnName, operator },
      )
    }

    const drizzleTable = drizzleTableOf(column)
    const tableName = getDrizzleTableName(drizzleTable) ?? 'unknown'

    let table = drizzleTable ? tableCache.get(drizzleTable) : undefined
    if (!table && drizzleTable) {
      table = extractEncryptionSchema(drizzleTable)
      tableCache.set(drizzleTable, table)
    }
    if (!table) {
      throw new EncryptionOperatorError(
        `Unable to resolve the encrypted table for column "${columnName}".`,
        { columnName, operator },
      )
    }

    const context: ColumnContext = {
      builder,
      table,
      indexes: builder.build().indexes,
      columnName,
      tableName,
      queryCast: queryCastForDomain(builder.getEqlType()),
    }
    contextCache.set(column, context)
    return context
  }

  /**
   * Gate an operator on the column's indexes. `indexes` is a disjunction — any
   * one of them grants the capability — so equality (`unique` OR `ore`) and the
   * single-index gates share one rule and one diagnostic shape.
   */
  function requireIndex(
    ctx: ColumnContext,
    indexes: readonly ('unique' | 'ore' | 'ope' | 'match' | 'ste_vec')[],
    operator: string,
    capability: string,
  ): void {
    if (!indexes.some((index) => ctx.indexes[index])) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires ${capability} on column "${ctx.columnName}" (domain ${ctx.builder.getEqlType()} does not support it).`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }
  }

  // Ordering flavour is pinned by the column's domain (eql-3.0.0): `_ord`
  // domains carry `ope` (`op` CLLW-OPE term), `_ord_ore` domains carry `ore`
  // (`ob` block-ORE term). Either satisfies the order/range operators, and an
  // order-capable column answers equality via its ordering term too.
  const EQUALITY_INDEXES = ['unique', 'ore', 'ope'] as const
  const ORDERING_INDEXES = ['ore', 'ope'] as const
  // Two DISTINCT operators, split by semantics (#617):
  // - `matches` is bloom free-text (`match`, a `text_search`/`text_match`
  //   column): a one-sided, order- and multiplicity-insensitive token match that
  //   may false-positive. It emits `eql_v3.matches(col, operand)` (the SQL
  //   function keeps its bundle name) but is NOT containment.
  // - `contains` is encrypted-JSONB containment (an `eql_v3_json_search` column,
  //   `ste_vec` index): exact jsonb `@>`, no false positives — genuine
  //   containment, so it keeps the `contains` name.
  const MATCH_INDEXES = ['match'] as const
  const JSON_CONTAINMENT_INDEXES = ['ste_vec'] as const

  function applyOperationOptions<T>(
    op: ChainableOperation<T>,
    opts?: EncryptionOperatorCallOpts,
  ): AuditableOperation<T> {
    const lockContext = opts?.lockContext ?? defaults.lockContext
    const audit = opts?.audit ?? defaults.audit
    const withLock = lockContext ? op.withLockContext(lockContext) : op
    if (audit) withLock.audit(audit)
    return withLock
  }

  function requireNonNullOperand(
    ctx: ColumnContext,
    value: unknown,
    operator: string,
  ): void {
    if (value == null) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" cannot encrypt a null operand for column "${ctx.columnName}". Use isNull() or isNotNull() for NULL checks.`,
        {
          columnName: ctx.columnName,
          tableName: ctx.tableName,
          operator,
        },
      )
    }
  }

  /**
   * Reject a free-text needle the column's match index cannot answer. A needle
   * shorter than the tokenizer's `token_length` yields an empty bloom filter,
   * and `stored_bf @> '{}'` holds for every row — so without this the query
   * silently returns the whole table.
   */
  function requireAnswerableNeedle(
    ctx: ColumnContext,
    value: unknown,
    operator: string,
  ): void {
    const match = ctx.indexes.match
    if (!match) return
    const reason = matchNeedleError(value, match)
    if (reason) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" cannot search column "${ctx.columnName}": ${reason}`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }
  }

  function operandFailure(
    ctx: ColumnContext,
    operator: string,
    reason: string,
  ): EncryptionOperatorError {
    return new EncryptionOperatorError(
      `Failed to encrypt query operand for "${ctx.columnName}": ${reason}`,
      { columnName: ctx.columnName, tableName: ctx.tableName, operator },
    )
  }

  /**
   * Render a query term as a cast operand: `'<json>'::eql_v3.query_<domain>`.
   * The cast is what reaches the bundle's `(domain, query_<domain>)` overloads —
   * a bare `::jsonb` would hit the storage-domain overload, whose CHECK demands
   * the ciphertext `c` a query term deliberately omits. `queryCast` is derived
   * from the column's own domain (see `queryCastForDomain`), so `sql.raw` is safe.
   */
  function castOperand(
    ctx: ColumnContext,
    operator: string,
    term: EncryptedQueryResult,
  ): SQL {
    if (ctx.queryCast === null) {
      throw operandFailure(
        ctx,
        operator,
        `column domain "${ctx.builder.getEqlType()}" has no query operand type.`,
      )
    }
    return sql`${JSON.stringify(term)}::${sql.raw(ctx.queryCast)}`
  }

  async function encryptOperand(
    ctx: ColumnContext,
    value: unknown,
    operator: string,
    queryType: QueryTypeName,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    requireNonNullOperand(ctx, value, operator)

    const result = await applyOperationOptions(
      client.encryptQuery(
        value as never,
        {
          table: ctx.table,
          column: ctx.builder,
          queryType,
        } as never,
      ),
      opts,
    )
    if (result.failure) {
      throw operandFailure(ctx, operator, result.failure.message)
    }
    return castOperand(ctx, operator, result.data)
  }

  /**
   * Encrypt a whole operand list in ONE `encryptQuery` batch crossing (rather
   * than one per value). The batch is position-stable, so the returned terms
   * align index-for-index with `values`; a response of a different length means
   * the contract was violated and is rejected rather than silently truncating
   * the predicate (which would widen an `inArray` or narrow a `notInArray`).
   * Null operands are rejected up front, so no term is filtered out of the batch.
   */
  async function encryptOperands(
    ctx: ColumnContext,
    values: unknown[],
    operator: string,
    queryType: QueryTypeName,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL[]> {
    for (const value of values) requireNonNullOperand(ctx, value, operator)

    const terms = values.map((value) => ({
      value,
      column: ctx.builder,
      table: ctx.table,
      queryType,
    }))
    const result = await applyOperationOptions(
      client.encryptQuery(terms as never),
      opts,
    )
    if (result.failure) {
      throw operandFailure(ctx, operator, result.failure.message)
    }

    const encrypted = result.data as EncryptedQueryResult[]
    if (encrypted.length !== values.length) {
      throw operandFailure(
        ctx,
        operator,
        `batch query encryption returned ${encrypted.length} terms for ${values.length} values.`,
      )
    }
    return encrypted.map((term) => castOperand(ctx, operator, term))
  }

  const colSql = (column: SQLWrapper): SQL => sql`${column}`

  async function equality(
    op: EqualityOp,
    left: SQLWrapper,
    right: unknown,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, op)
    requireIndex(ctx, EQUALITY_INDEXES, op, 'equality')
    const enc = await encryptOperand(ctx, right, op, 'equality', opts)
    return v3Dialect.equality(op, colSql(left), enc)
  }

  async function comparison(
    op: ComparisonOp,
    left: SQLWrapper,
    right: unknown,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, op)
    requireIndex(ctx, ORDERING_INDEXES, op, 'order/range')
    const enc = await encryptOperand(ctx, right, op, 'orderAndRange', opts)
    return v3Dialect.comparison(op, colSql(left), enc)
  }

  async function range(
    left: SQLWrapper,
    min: unknown,
    max: unknown,
    negate: boolean,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, operator)
    requireIndex(ctx, ORDERING_INDEXES, operator, 'order/range')
    // Independent operands — encrypt concurrently rather than paying two
    // sequential round-trips to the crypto backend.
    const [encMin, encMax] = await Promise.all([
      encryptOperand(ctx, min, operator, 'orderAndRange', opts),
      encryptOperand(ctx, max, operator, 'orderAndRange', opts),
    ])
    // `v3Dialect.range` is already parenthesised, so `NOT` binds to the whole
    // conjunction without a wrapper here.
    const condition = v3Dialect.range(colSql(left), encMin, encMax)
    return negate ? sql`NOT ${condition}` : condition
  }

  /**
   * Fuzzy free-text token match on a `text_search`/`text_match` column. NOT
   * containment: it tests whether the needle's downcased 3-gram set is a subset
   * of the haystack's, via a bloom filter — order- and multiplicity-insensitive
   * and one-sided (a `true` may be a false positive, a `false` never is). Emits
   * `eql_v3.matches(col, operand)` (the SQL function's bundle name).
   */
  async function matches(
    left: SQLWrapper,
    right: unknown,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, operator)
    requireIndex(ctx, MATCH_INDEXES, operator, 'free-text search')
    // The answerable-needle rule applies (a sub-`token_length` needle blooms to
    // nothing and would match every row); the `query_<domain>` cast reaches the
    // match overload.
    requireAnswerableNeedle(ctx, right, operator)
    const enc = await encryptOperand(
      ctx,
      right,
      operator,
      'freeTextSearch',
      opts,
    )
    return v3Dialect.contains(colSql(left), enc)
  }

  /**
   * Exact encrypted-JSONB containment on an `eql_v3_json_search` (`ste_vec`) column:
   * genuine jsonb `@>`, no false positives — hence it keeps the `contains` name.
   * `eql_v3_json_search` has no `eql_v3.matches` overload; containment is the `@>`
   * operator, whose `(eql_v3_json_search, eql_v3.query_json)` form takes a NARROWED
   * query term (searchableJson → no ciphertext), cast to `eql_v3.query_json`.
   */
  async function containsJsonOp(
    left: SQLWrapper,
    right: unknown,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, operator)
    requireIndex(ctx, JSON_CONTAINMENT_INDEXES, operator, 'JSON containment')
    const needle = await encryptJsonContainmentTerm(ctx, right, operator, opts)
    return v3Dialect.containsJson(colSql(left), needle)
  }

  /**
   * Build a `query_json` containment needle for a `json` column — the JSON query
   * term carries no ciphertext and satisfies the `eql_v3.query_json` CHECK the
   * `@>` overload needs. Cast here (not by `queryCastForDomain`): a json column's
   * domain is `eql_v3_json_search` but its query operand type is the irregular
   * `eql_v3.query_json`.
   */
  async function encryptJsonContainmentTerm(
    ctx: ColumnContext,
    value: unknown,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    requireNonNullOperand(ctx, value, operator)
    // Reject the empty-object needle. `doc @> '{}'` holds for EVERY document
    // (jsonb `{} ⊆ anything`), so `contains(col, {})` would silently return the
    // whole table — the same whole-table footgun the bloom path guards against
    // with `requireAnswerableNeedle`. An accidental empty filter is a bug, not a
    // match-all request; callers wanting every row should omit the predicate.
    if (
      value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      Object.keys(value).length === 0
    ) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" cannot take an empty object needle on column "${ctx.columnName}": it matches every row. Pass a non-empty sub-object, or omit the predicate to select all rows.`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }
    const result = await applyOperationOptions(
      client.encryptQuery(
        value as never,
        {
          table: ctx.table,
          column: ctx.builder,
          queryType: 'searchableJson',
        } as never,
      ),
      opts,
    )
    if (result.failure) {
      throw operandFailure(ctx, operator, result.failure.message)
    }
    return sql`${JSON.stringify(result.data)}::eql_v3.query_json`
  }

  /**
   * JSONPath selector-with-constraint on an `eql_v3_json_search` (`ste_vec`)
   * column. Equality uses a value-selector containment needle, allowing the
   * functional GIN index to answer the query. Ordering extracts the path entry
   * with a selector hash and compares it to a ciphertext-free scalar ordering
   * term. No storage ciphertext is placed in the WHERE clause.
   */
  async function selectorCompare(
    col: SQLWrapper,
    path: string,
    op: EqualityOp | ComparisonOp,
    value: unknown,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(col, operator)
    requireIndex(
      ctx,
      JSON_CONTAINMENT_INDEXES,
      operator,
      'JSON selector (searchableJson)',
    )
    requireNonNullOperand(ctx, value, operator)

    // A selector compares a scalar leaf — reject non-scalars / non-orderable
    // types up front with a clear error, not a deferred DB failure.
    const ordering = op !== 'eq' && op !== 'ne'
    const leafReason = unsupportedLeafReason(value, ordering)
    if (leafReason) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" cannot compare column "${ctx.columnName}": ${leafReason}`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }

    // Surface path-validation failures as EncryptionOperatorError with context.
    let segments: string[]
    try {
      segments = parseSelectorSegments(path)
    } catch (err) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" on column "${ctx.columnName}": ${err instanceof Error ? err.message : String(err)}`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }

    const canonicalPath = jsonPathOf(segments)

    if (op === 'eq' || op === 'ne') {
      const result = await applyOperationOptions(
        client.encryptQuery(
          { path: canonicalPath, value } as never,
          {
            table: ctx.table,
            column: ctx.builder,
            queryType: 'steVecValueSelector',
          } as never,
        ),
        opts,
      )
      if (result.failure) {
        throw operandFailure(ctx, operator, result.failure.message)
      }
      const contains = v3Dialect.containsJson(
        colSql(col),
        sql`${JSON.stringify(result.data)}::eql_v3.query_json`,
      )
      return op === 'eq'
        ? contains
        : sql`(NOT ${contains} OR ${colSql(col)} IS NULL)`
    }

    // Selector hashing and scalar-term encryption are independent, so order
    // them concurrently. `steVecTerm` accepts only the JSON-orderable scalar
    // families (string and number), enforced above.
    const [selResult, termResult] = await Promise.all([
      applyOperationOptions(
        client.encryptQuery(
          canonicalPath as never,
          {
            table: ctx.table,
            column: ctx.builder,
            queryType: 'steVecSelector',
          } as never,
        ),
        opts,
      ),
      applyOperationOptions(
        client.encryptQuery(
          value as never,
          {
            table: ctx.table,
            column: ctx.builder,
            queryType: 'steVecTerm',
          } as never,
        ),
        opts,
      ),
    ])
    if (selResult.failure) {
      throw operandFailure(ctx, operator, selResult.failure.message)
    }
    if (termResult.failure) {
      throw operandFailure(ctx, operator, termResult.failure.message)
    }

    // A v3 selector term is the bare HMAC hash string; guard the shape so a
    // wrapped envelope can't silently bind as a JSON blob and match no rows.
    const selValue = selResult.data
    if (typeof selValue !== 'string') {
      throw operandFailure(
        ctx,
        operator,
        `expected a bare selector hash, got ${typeof selValue}.`,
      )
    }

    const selSql = sql`${selValue}::text`
    const leftEntry = v3Dialect.selectorEntry(colSql(col), selSql)
    const termCast =
      typeof value === 'string'
        ? 'eql_v3.query_text_ord'
        : 'eql_v3.query_double_ord'
    const rightTerm = sql`${JSON.stringify(termResult.data)}::${sql.raw(termCast)}`
    return v3Dialect.comparison(op, leftEntry, rightTerm)
  }

  /** Comparison methods bound to a `col->'path'` selector, mirroring the scalar
   * operators. Async: each encrypts its operand. */
  function selectorOps(col: SQLWrapper, path: string) {
    const at =
      (op: EqualityOp | ComparisonOp) =>
      (value: unknown, opts?: EncryptionOperatorCallOpts) =>
        selectorCompare(col, path, op, value, `selector(${path}).${op}`, opts)
    return {
      /** `col->'path' = value` (encrypted equality at the selector). A row whose
       * document lacks `path` is excluded (it is not equal to `value`). */
      eq: at('eq'),
      /** `col->'path' <> value`, INCLUDING rows whose document lacks `path`
       * ("not equal to value" covers "has no value"). */
      ne: at('ne'),
      /** `col->'path' > value` (encrypted ordering at the selector). */
      gt: at('gt'),
      /** `col->'path' >= value`. */
      gte: at('gte'),
      /** `col->'path' < value`. */
      lt: at('lt'),
      /** `col->'path' <= value`. */
      lte: at('lte'),
      /** Order rows ascending by the encrypted scalar at `path`. Missing paths
       * produce SQL NULL and follow PostgreSQL's normal NULL ordering. */
      asc: (opts?: EncryptionOperatorCallOpts) =>
        selectorOrder(col, path, 'asc', opts),
      /** Order rows descending by the encrypted scalar at `path`. Missing paths
       * produce SQL NULL and follow PostgreSQL's normal NULL ordering. */
      desc: (opts?: EncryptionOperatorCallOpts) =>
        selectorOrder(col, path, 'desc', opts),
    }
  }

  /** Build `ORDER BY eql_v3.ord_term(col -> selector::text)`.
   * The selector is encrypted, but the extracted SteVec entry already carries
   * its OPE ordering term, so no plaintext comparison operand is needed. */
  async function selectorOrder(
    col: SQLWrapper,
    path: string,
    direction: 'asc' | 'desc',
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const operator = `selector(${path}).${direction}`
    const ctx = resolveContext(col, operator)
    requireIndex(
      ctx,
      JSON_CONTAINMENT_INDEXES,
      operator,
      'JSON selector (searchableJson)',
    )

    let canonicalPath: string
    try {
      canonicalPath = jsonPathOf(parseSelectorSegments(path))
    } catch (err) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" on column "${ctx.columnName}": ${err instanceof Error ? err.message : String(err)}`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }

    const result = await applyOperationOptions(
      client.encryptQuery(
        canonicalPath as never,
        {
          table: ctx.table,
          column: ctx.builder,
          queryType: 'steVecSelector',
        } as never,
      ),
      opts,
    )
    if (result.failure) {
      throw operandFailure(ctx, operator, result.failure.message)
    }
    if (typeof result.data !== 'string') {
      throw operandFailure(
        ctx,
        operator,
        `expected a bare selector hash, got ${typeof result.data}.`,
      )
    }

    const entry = v3Dialect.selectorEntry(
      colSql(col),
      sql`${result.data}::text`,
    )
    const term = v3Dialect.orderBy(entry, 'ope')
    return direction === 'asc' ? asc(term) : desc(term)
  }

  async function inArrayOp(
    left: SQLWrapper,
    values: unknown[],
    negate: boolean,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, operator)
    if (values.length === 0) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires a non-empty list of values for column "${ctx.columnName}".`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }
    // Gate and resolve the context once for the whole list, then encrypt it in
    // a single `encryptQuery` batch crossing.
    requireIndex(ctx, EQUALITY_INDEXES, operator, 'equality')
    const op: EqualityOp = negate ? 'ne' : 'eq'
    const encrypted = await encryptOperands(
      ctx,
      values,
      operator,
      'equality',
      opts,
    )
    const conditions = encrypted.map((enc) =>
      v3Dialect.equality(op, colSql(left), enc),
    )
    // The empty-list guard above leaves `conditions` non-empty, so `and`/`or`
    // never return undefined here.
    return (negate ? and(...conditions) : or(...conditions)) as SQL
  }

  function orderTerm(column: SQLWrapper, operator: string): SQL {
    const ctx = resolveContext(column, operator)
    requireIndex(ctx, ORDERING_INDEXES, operator, 'order/range')
    return v3Dialect.orderBy(colSql(column), ctx.indexes.ore ? 'ore' : 'ope')
  }

  async function combine(
    joiner: typeof and,
    empty: SQL,
    conditions: (SQL | SQLWrapper | Promise<SQL> | undefined)[],
  ): Promise<SQL> {
    const present = conditions.filter(
      (c): c is SQL | SQLWrapper | Promise<SQL> => c !== undefined,
    )
    const resolved = await Promise.all(present)
    return joiner(...resolved) ?? empty
  }

  return {
    /** Equality: `column = value`. Encrypts `r` and emits `eql_v3.eq`.
     * Requires a `unique` or `ore` index on the column. */
    eq: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      equality('eq', l, r, opts),
    /** Inequality: `column <> value`. Encrypts `r` and emits `eql_v3.neq`.
     * Requires a `unique` or `ore` index on the column. */
    ne: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      equality('ne', l, r, opts),
    /** Greater-than: `column > value`. Encrypts `r` and emits `eql_v3.gt`.
     * Requires an `ore` (order/range) index. */
    gt: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('gt', l, r, opts),
    /** Greater-than-or-equal: `column >= value`. Encrypts `r` and emits
     * `eql_v3.gte`. Requires an `ore` (order/range) index. */
    gte: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('gte', l, r, opts),
    /** Less-than: `column < value`. Encrypts `r` and emits `eql_v3.lt`.
     * Requires an `ore` (order/range) index. */
    lt: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('lt', l, r, opts),
    /** Less-than-or-equal: `column <= value`. Encrypts `r` and emits
     * `eql_v3.lte`. Requires an `ore` (order/range) index. */
    lte: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('lte', l, r, opts),
    /** Inclusive range `min <= column <= max`. Encrypts both bounds
     * concurrently. Requires an `ore` (order/range) index. */
    between: (
      l: SQLWrapper,
      min: unknown,
      max: unknown,
      opts?: EncryptionOperatorCallOpts,
    ) => range(l, min, max, false, 'between', opts),
    /** Negated inclusive range `NOT (min <= column <= max)`. Encrypts both
     * bounds concurrently. Requires an `ore` (order/range) index. */
    notBetween: (
      l: SQLWrapper,
      min: unknown,
      max: unknown,
      opts?: EncryptionOperatorCallOpts,
    ) => range(l, min, max, true, 'notBetween', opts),
    /** Fuzzy free-text token match — the needle's 3-gram set is (bloom-)tested
     * as a subset of the column's. NOT containment: order/multiplicity-
     * insensitive and one-sided (a `true` may be a false positive). Encrypts
     * `r`. Requires a `match` (free-text search) index. */
    matches: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      matches(l, r, 'matches', opts),
    /** Exact encrypted-JSONB containment (`@>`): matches rows whose document
     * contains the given sub-object. No false positives. Encrypts `r`. Requires
     * a `ste_vec` index (a `types.Json` column). */
    contains: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      containsJsonOp(l, r, 'contains', opts),
    /** JSONPath selector-with-constraint on a `types.Json` (`ste_vec`) column.
     * Returns comparison and ordering methods bound to `col->'path'` — e.g.
     * `await ops.selector(users.doc, '$.age').gt(21)` emits
     * `col->'<sel>' > <entry>`, while `.asc()` emits
     * `ORDER BY eql_v3.ord_term(col->'<sel>')`. Its unique power over `contains`
     * is ordering at a path (`gt`/`gte`/`lt`/`lte` and `asc`/`desc`); `eq`/`ne`
     * are also provided. Dot-notation object paths only in v1. */
    selector: (l: SQLWrapper, path: string) => selectorOps(l, path),
    /** Membership: ORs one encrypted `eq` term per value. The whole list is
     * encrypted in one `encryptQuery` batch crossing. Rejects an empty list;
     * requires a `unique` or `ore` index. */
    inArray: (
      l: SQLWrapper,
      values: unknown[],
      opts?: EncryptionOperatorCallOpts,
    ) => inArrayOp(l, values, false, 'inArray', opts),
    /** Non-membership: ANDs one encrypted `ne` term per value. The whole list
     * is encrypted in one `encryptQuery` batch crossing. Rejects an empty list;
     * requires a `unique` or `ore` index. */
    notInArray: (
      l: SQLWrapper,
      values: unknown[],
      opts?: EncryptionOperatorCallOpts,
    ) => inArrayOp(l, values, true, 'notInArray', opts),
    /** Ascending order by the encrypted order term (`eql_v3.ord_term` /
     * `eql_v3.ord_term_ore`, by the column's ordering flavour).
     * Synchronous (no operand to encrypt). Requires an ordering index. */
    asc: (c: SQLWrapper) => asc(orderTerm(c, 'asc')),
    /** Descending order by the encrypted order term (`eql_v3.ord_term` /
     * `eql_v3.ord_term_ore`, by the column's ordering flavour).
     * Synchronous (no operand to encrypt). Requires an ordering index. */
    desc: (c: SQLWrapper) => desc(orderTerm(c, 'desc')),
    /** Conjunction of the given conditions, awaiting any async operands and
     * dropping `undefined`. Empty input resolves to `true`. */
    and: (...conds: (SQL | SQLWrapper | Promise<SQL> | undefined)[]) =>
      combine(and, sql`true`, conds),
    /** Disjunction of the given conditions, awaiting any async operands and
     * dropping `undefined`. Empty input resolves to `false`. */
    or: (...conds: (SQL | SQLWrapper | Promise<SQL> | undefined)[]) =>
      combine(or, sql`false`, conds),
    /** Drizzle's `isNull`, re-exported unchanged — `column IS NULL` needs no
     * encryption and works on any (nullable) encrypted column. */
    isNull,
    /** Drizzle's `isNotNull`, re-exported unchanged — `column IS NOT NULL`
     * needs no encryption. */
    isNotNull,
    /** Drizzle's `not`, re-exported unchanged — negates an already-built
     * (encrypted) predicate. Safe over any operator here, including `between`,
     * whose fragment is self-parenthesising. */
    not,
    /** Drizzle's `exists`, re-exported unchanged — for correlated subqueries. */
    exists,
    /** Drizzle's `notExists`, re-exported unchanged — for correlated
     * subqueries. */
    notExists,
  }
}
