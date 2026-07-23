import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import { logger, matchNeedleError } from '@cipherstash/stack/adapter-kit'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import {
  type EncryptionError,
  EncryptionErrorTypes,
} from '@cipherstash/stack/errors'
import type { LockContextInput } from '@cipherstash/stack/identity'
import type {
  Encrypted,
  EncryptedQueryResult,
  QueryTypeName,
  ScalarQueryTerm,
} from '@cipherstash/stack/types'
import type { ColumnMap, V3ColumnLike } from './column-map'
import {
  isEncryptableTerm,
  isEncryptedColumn,
  mapFilterOpToQueryType,
} from './helpers'
import type { DbQuerySpace, FilterOp } from './types'

export class EncryptionFailedError extends Error {
  public encryptionError: EncryptionError

  constructor(message: string, encryptionError: EncryptionError) {
    super(message)
    this.name = 'EncryptionFailedError'
    this.encryptionError = encryptionError
  }
}

export type TermMapping =
  | { source: 'filter'; filterIndex: number; inIndex?: number }
  | { source: 'match'; matchIndex: number; column: string }
  | { source: 'not'; notIndex: number; inIndex?: number }
  | { source: 'raw'; rawIndex: number; inIndex?: number }
  | {
      source: 'or-string'
      orIndex: number
      conditionIndex: number
      inIndex?: number
    }
  | {
      source: 'or-structured'
      orIndex: number
      conditionIndex: number
      inIndex?: number
    }

export type EncryptedFilterState = {
  // `EncryptedQueryResult[]`, not `unknown[]` — `encryptCollectedTerms` returns
  // that type, and typing the field to match is what lets the restored envelope
  // type reach the use site (`encryptedValues[i]`) instead of widening back to
  // `unknown` at this boundary.
  encryptedValues: EncryptedQueryResult[]
  termMap: TermMapping[]
}

/**
 * Everything an encryption step needs from the builder. Assembled per
 * `execute()`, so `lockContext`/`auditConfig` are read at execution time — not
 * captured when the builder was constructed.
 */
export type EncryptionContext = {
  tableName: string
  table: AnyV3Table
  encryptionClient: EncryptionClient
  lockContext: LockContextInput | null
  auditConfig: AuditConfig | null
  columns: ColumnMap
  /** EQL 3.0.2+ requires query-domain casts PostgREST cannot express. */
  queryDomainsRequired: boolean
}

/**
 * Apply the builder's lock context and audit config to a pending operation.
 *
 * Every encrypt/decrypt crossing in this adapter goes through the same three
 * steps, and they must stay identical: an operation that silently skipped the
 * lock context would encrypt under the wrong data key.
 */
export function withOpContext<R>(
  baseOp: PromiseLike<R> & {
    withLockContext(
      lockContext: LockContextInput,
    ): PromiseLike<R> & { audit(config: AuditConfig): unknown }
    audit(config: AuditConfig): unknown
  },
  ctx: Pick<EncryptionContext, 'lockContext' | 'auditConfig'>,
): PromiseLike<R> {
  const op = ctx.lockContext ? baseOp.withLockContext(ctx.lockContext) : baseOp
  if (ctx.auditConfig) op.audit(ctx.auditConfig)
  return op
}

/**
 * EQL 3.0.2 removed the storage/jsonb escape hatch for free-text and JSON
 * operators: those now require typed query-domain operands PostgREST cannot
 * express. Fail before encryption, so a decryptable storage envelope never
 * enters a GET URL.
 */
export function assertPostgrestCanQueryEncryptedOperator(
  queryDomainsRequired: boolean,
  method: string,
  column: string,
): void {
  if (!queryDomainsRequired) return
  throw new Error(
    `[supabase v3]: ${method}() on encrypted column "${column}" is unavailable with EQL 3.0.2+: the SQL operator requires an eql_v3.query_* cast that PostgREST cannot express. Use the Drizzle or Prisma Next adapter, or a scoped SQL/RPC function.`,
  )
}

/**
 * Validate an encrypted-JSON containment operand: a NON-EMPTY plain object or a
 * non-empty array. Everything else is rejected with an actionable steer:
 *
 * - Scalars/strings: the caller meant free-text (`matches` on a text column) or
 *   a selector — a raw JSON string is NOT parsed, by design (parsing would make
 *   `'{"a":1}'` and `{a:1}` silently different queries on other surfaces).
 * - Non-plain objects (`Date`, `Map`, `RegExp`, class instances): these JSON-
 *   serialize to scalars or `{}` — not the sub-document the caller believes.
 * - `{}` and `[]`: jsonb containment holds for EVERY document (`doc @> '{}'`),
 *   so an accidentally-empty needle would silently return (and decrypt) the
 *   whole table. The Drizzle adapter rejects the same needle for the same
 *   reason — the two first-party adapters must agree that this is an error.
 */
export function assertJsonContainmentOperand(
  column: string,
  value: unknown,
): void {
  const isPlainObject =
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  if (!isPlainObject && !Array.isArray(value)) {
    // Array.isArray is false on this branch by construction, so the label only
    // distinguishes null / non-plain object / scalar.
    const got =
      value === null
        ? 'null'
        : typeof value === 'object'
          ? (value as object).constructor?.name || 'a non-plain object'
          : typeof value
    throw new Error(
      `[supabase v3]: encrypted JSON containment on column "${column}" takes a sub-document (plain object or array) to match, got ${got}.`,
    )
  }
  const empty = Array.isArray(value)
    ? value.length === 0
    : Object.keys(value as object).length === 0
  if (empty) {
    throw new Error(
      `[supabase v3]: encrypted JSON containment on column "${column}" cannot take an empty ${Array.isArray(value) ? 'array' : 'object'} needle: it matches every row. Pass a non-empty sub-document, or omit the predicate to select all rows.`,
    )
  }
}

/**
 * Resolve a raw `.filter()` operator to the capability it exercises. A
 * supported v3 operand is a full storage envelope, so `queryType` never
 * selects a narrowing — it only tells {@link assertTermQueryable} which
 * capability to demand of the column.
 *
 * Unknown operators throw rather than silently defaulting to equality, which
 * would encrypt a term the column may not even be able to compare.
 */
export function queryTypeForRawOp(operator: string): QueryTypeName {
  switch (operator) {
    case 'cs':
      return 'freeTextSearch'
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte':
      return 'orderAndRange'
    case 'eq':
    case 'neq':
    case 'in':
    case 'is':
      return 'equality'
    default:
      throw new Error(
        `[supabase v3]: unsupported raw filter operator "${operator}" on an encrypted column`,
      )
  }
}

/**
 * The CipherStash query type for an `.or()` condition's operator on an
 * encrypted column. String-form conditions carry raw PostgREST operators
 * (`cs`), which are not {@link FilterOp}s.
 */
export function queryTypeForOrOp(op: FilterOp): QueryTypeName {
  if (op === 'matches') return 'freeTextSearch'
  // Structured conditions may carry the `contains` METHOD spelling (the wire
  // token becomes `cs` in rebuildOrString). It maps to the same capability
  // gate as `cs`; on a JSON column the term resolver then re-types it to
  // searchableJson and validates the operand. selectorNe's IS-NULL-inclusive
  // or-form relies on this arm.
  if (op === 'contains') return 'freeTextSearch'
  return queryTypeForRawOp(op)
}

function encryptionFailure(
  tableName: string,
  message: string,
  cause?: EncryptionError,
): never {
  logger.error(
    `Supabase: failed to encrypt query terms for table "${tableName}"`,
  )
  // Most callers pass the operation's own `EncryptionError`; the contract-
  // violation cases (bulk length mismatch, null envelope) have none, so
  // synthesize one — a broken query encryption is still an encryption failure,
  // and callers branch on `error.encryptionError` regardless.
  throw new EncryptionFailedError(
    `Failed to encrypt query terms: ${message}`,
    cause ?? { type: EncryptionErrorTypes.EncryptionError, message },
  )
}

// ---------------------------------------------------------------------------
// Step 3: Encrypt filter values
// ---------------------------------------------------------------------------

export async function encryptFilterValues(
  dbSpace: DbQuerySpace,
  ctx: EncryptionContext,
): Promise<EncryptedFilterState> {
  // Collect all terms that need encryption
  const terms: ScalarQueryTerm[] = []
  const termMap: TermMapping[] = []

  const tableColumns = ctx.columns.queryColumnMap()
  const encryptedColumnNames = ctx.columns.encryptedColumnNames

  const pushTerm = (
    value: JsPlaintext,
    column: ScalarQueryTerm['column'],
    queryType: QueryTypeName,
    mapping: TermMapping,
  ) => {
    terms.push({
      value,
      column,
      table: ctx.table,
      queryType,
      returnType: 'composite-literal',
    })
    termMap.push(mapping)
  }

  /**
   * Collect one term per element of an `in`-list operand.
   *
   * Element-wise is the only correct encoding: encrypting the array as ONE
   * value collapses `(a,b)` into a single ciphertext that matches nothing. A
   * null element is SQL NULL and passes through unencrypted; the applier
   * restores it by index, which is why the mapping carries `inIndex`.
   *
   * Shared by the regular-`in`, `not(…,'in',…)` and or-condition paths. They
   * drifted apart once already — the `not` path went unfixed while the other
   * two encrypted element-wise — so they are kept in lockstep here rather than
   * spelled out three times.
   */
  const collectInListTerms = (
    op: FilterOp,
    values: readonly unknown[],
    column: ScalarQueryTerm['column'],
    queryType: QueryTypeName,
    mappingFor: (inIndex: number) => TermMapping,
  ) => {
    for (let j = 0; j < values.length; j++) {
      if (!isEncryptableTerm(op, values[j])) continue
      pushTerm(values[j] as JsPlaintext, column, queryType, mappingFor(j))
    }
  }

  // Regular filters
  for (let i = 0; i < dbSpace.filters.length; i++) {
    const f = dbSpace.filters[i]
    if (!isEncryptedColumn(f.column, encryptedColumnNames)) continue

    const column = tableColumns[f.column]
    if (!column) continue

    if (f.op === 'in' && Array.isArray(f.value)) {
      collectInListTerms(
        f.op,
        f.value,
        column,
        mapFilterOpToQueryType(f.op),
        (inIndex) => ({ source: 'filter', filterIndex: i, inIndex }),
      )
    } else if (!isEncryptableTerm(f.op, f.value)) {
      // `is` predicate or null operand — forwarded unencrypted.
    } else {
      pushTerm(f.value as JsPlaintext, column, mapFilterOpToQueryType(f.op), {
        source: 'filter',
        filterIndex: i,
      })
    }
  }

  // Match filters
  for (let i = 0; i < dbSpace.matchFilters.length; i++) {
    const mf = dbSpace.matchFilters[i]
    for (const { column: colName, value } of mf.entries) {
      if (!isEncryptedColumn(colName, encryptedColumnNames)) continue
      // `match` carries no operator; equality is implied.
      if (!isEncryptableTerm('eq', value)) continue
      const column = tableColumns[colName]
      if (!column) continue

      pushTerm(value as JsPlaintext, column, 'equality', {
        source: 'match',
        matchIndex: i,
        column: colName,
      })
    }
  }

  // Not filters
  for (let i = 0; i < dbSpace.notFilters.length; i++) {
    const nf = dbSpace.notFilters[i]
    if (!isEncryptedColumn(nf.column, encryptedColumnNames)) continue
    if (!isEncryptableTerm(nf.op, nf.value)) continue
    const column = tableColumns[nf.column]
    if (!column) continue

    if (nf.op === 'in') {
      // A PostgREST list literal (`'(a,b)'`) cannot be encrypted element-wise,
      // and encrypting it whole matches nothing. Refuse it rather than emit a
      // filter that silently returns no rows.
      if (!Array.isArray(nf.value)) {
        throw new Error(
          `not("${nf.column}", "in", …) on an encrypted column requires an array of values, ` +
            `not a PostgREST list literal — each element must be encrypted separately`,
        )
      }
      collectInListTerms(
        nf.op,
        nf.value,
        column,
        mapFilterOpToQueryType(nf.op),
        (inIndex) => ({ source: 'not', notIndex: i, inIndex }),
      )
      continue
    }

    pushTerm(nf.value as JsPlaintext, column, mapFilterOpToQueryType(nf.op), {
      source: 'not',
      notIndex: i,
    })
  }

  // Or filters — conditions were parsed once, in `toDbSpace`. The string and
  // structured forms differ only in their `source` tag; the encryption rules,
  // including the `in`-list split below, are identical.
  for (let i = 0; i < dbSpace.orFilters.length; i++) {
    const of_ = dbSpace.orFilters[i]
    const source = of_.kind === 'string' ? 'or-string' : 'or-structured'

    for (let j = 0; j < of_.conditions.length; j++) {
      const cond = of_.conditions[j]
      if (!isEncryptedColumn(cond.column, encryptedColumnNames)) continue
      const column = tableColumns[cond.column]
      if (!column) continue

      // `queryTypeForOrOp`, not `mapFilterOpToQueryType`: an or-condition may
      // carry a raw PostgREST operator (`cs`), which is not a `FilterOp`.
      const queryType = queryTypeForOrOp(cond.op)
      const mappingFor = (inIndex?: number): TermMapping => ({
        source,
        orIndex: i,
        conditionIndex: j,
        inIndex,
      })

      if (cond.op === 'in' && Array.isArray(cond.value)) {
        collectInListTerms(cond.op, cond.value, column, queryType, mappingFor)
        continue
      }

      if (!isEncryptableTerm(cond.op, cond.value)) continue
      pushTerm(cond.value as JsPlaintext, column, queryType, mappingFor())
    }
  }

  // Raw filters
  for (let i = 0; i < dbSpace.rawFilters.length; i++) {
    const rf = dbSpace.rawFilters[i]
    if (!isEncryptedColumn(rf.column, encryptedColumnNames)) continue
    const column = tableColumns[rf.column]
    if (!column) continue

    if (rf.operator === 'in') {
      // Same contract as the `not(…, 'in', …)` path: a PostgREST list literal
      // (`'("a","b")'`) cannot be encrypted element-wise, and encrypting it
      // whole matches nothing. Refuse it rather than emit a filter that
      // silently returns no rows.
      if (!Array.isArray(rf.value)) {
        throw new Error(
          `filter("${rf.column}", "in", …) on an encrypted column requires an array of values, ` +
            `not a PostgREST list literal — each element must be encrypted separately`,
        )
      }
      collectInListTerms(
        'in',
        rf.value,
        column,
        queryTypeForRawOp(rf.operator),
        (inIndex) => ({ source: 'raw', rawIndex: i, inIndex }),
      )
      continue
    }

    if (!isEncryptableTerm(rf.operator, rf.value)) continue

    pushTerm(rf.value as JsPlaintext, column, queryTypeForRawOp(rf.operator), {
      source: 'raw',
      rawIndex: i,
    })
  }

  if (terms.length === 0) {
    return { encryptedValues: [], termMap: [] }
  }

  const encryptedValues = await encryptCollectedTerms(terms, ctx)
  return { encryptedValues, termMap }
}

/**
 * Encrypt every filter operand as a full storage envelope, serialized to jsonb
 * text for the PostgREST filter value.
 *
 * Terms are grouped by column and each group takes ONE `bulkEncrypt` crossing.
 * `in(col, [a, b, c])` collects one term per element (the list must never be
 * encrypted whole), so encrypting per term spent N ZeroKMS/FFI round-trips
 * where one would do. `bulkEncrypt` carries a single `{table, column}` for the
 * whole payload, so the grouping is mandatory, not an optimisation: one bulk
 * call over a mixed-column term array would stamp one column onto every
 * plaintext. Results are scattered back onto the terms' original indices,
 * which is the contract `termMap` downstream relies on.
 *
 * Mirrors `eql/v3/drizzle/operators.ts` `encryptOperands` — same batching
 * contract, same length assertion, same fallback. Kept separate because that
 * one encrypts a single-column operand list and returns `SQL[]`, while this
 * must group a multi-column term array and preserve positions.
 */
async function encryptCollectedTerms(
  terms: ScalarQueryTerm[],
  ctx: EncryptionContext,
): Promise<EncryptedQueryResult[]> {
  const groups = new Map<
    V3ColumnLike,
    { indices: number[]; values: ScalarQueryTerm['value'][] }
  >()
  terms.forEach((term, index) => {
    const column = assertTermQueryable(term, ctx)
    const group = groups.get(column) ?? { indices: [], values: [] }
    group.indices.push(index)
    group.values.push(term.value)
    groups.set(column, group)
  })

  const bulkEncrypt = ctx.encryptionClient.bulkEncrypt?.bind(
    ctx.encryptionClient,
  )
  // Each term becomes the `JSON.stringify`'d storage envelope — a `string`,
  // which is one arm of `EncryptedQueryResult`. PostgREST cannot cast a filter
  // value to the `eql_v3.query_<name>` twins, so v3 sends full envelopes,
  // serialized to jsonb text.
  const results = new Array<EncryptedQueryResult>(terms.length)

  await Promise.all(
    Array.from(groups, async ([column, { indices, values }]) => {
      const encrypted = bulkEncrypt
        ? await bulkEncryptGroup(bulkEncrypt, column, values, ctx)
        : await encryptGroupPerTerm(column, values, ctx)

      encrypted.forEach((envelope, i) => {
        results[indices[i]] = JSON.stringify(envelope)
      })
    }),
  )

  return results
}

/**
 * Validate a term's query type against its column's declared capabilities.
 * Pure validation: `encrypt`/`bulkEncrypt` never receive the query type. On
 * EQL 3.0.2+, free-text/JSON terms are rejected before this storage-encryption
 * path can place ciphertext in a GET URL.
 *
 * Exported for direct testing: no public call path can produce an unsupported
 * `queryType` (`mapFilterOpToQueryType`, {@link queryTypeForRawOp} and
 * {@link queryTypeForOrOp} are exhaustive), so that backstop is only reachable
 * by calling this with a hand-built term.
 */
export function assertTermQueryable(
  term: ScalarQueryTerm,
  ctx: EncryptionContext,
): V3ColumnLike {
  const column = term.column as unknown as V3ColumnLike
  let queryType = term.queryType ?? 'equality'
  const capabilities = column.getQueryCapabilities()

  // The `cs` wire operator is capability-overloaded: bloom free-text on a
  // match/search TEXT column, encrypted ste_vec containment on a `types.Json`
  // DOCUMENT column. Both arrive here as `freeTextSearch` (contains/matches/
  // raw `cs` all map there); resolve to the capability the column actually
  // carries. The two are mutually exclusive by construction, so this can
  // never reinterpret a real free-text column.
  if (
    queryType === 'freeTextSearch' &&
    !capabilities.freeTextSearch &&
    capabilities.searchableJson
  ) {
    queryType = 'searchableJson'
  }

  if (
    queryType !== 'equality' &&
    queryType !== 'orderAndRange' &&
    queryType !== 'freeTextSearch' &&
    queryType !== 'searchableJson'
  ) {
    throw new Error(
      `[supabase v3]: query type "${queryType}" is not supported on EQL v3 columns`,
    )
  }

  if (!capabilities[queryType]) {
    throw new Error(
      `[supabase v3]: column "${column.getName()}" (${column.getEqlType()}) does not support ${queryType} queries — declare the column with a domain that carries that capability`,
    )
  }

  if (queryType === 'freeTextSearch' || queryType === 'searchableJson') {
    // This is the common boundary for every spelling that collects an
    // encrypted match/containment term: matches(), contains(), not(), raw
    // filter(), and both forms of or(). Method-level checks provide earlier
    // errors for the direct helpers, but cannot cover the raw filter paths on
    // their own.
    assertPostgrestCanQueryEncryptedOperator(
      ctx.queryDomainsRequired,
      'filter',
      column.getName(),
    )
  }

  if (queryType === 'searchableJson') {
    // THE single enforced operand boundary for encrypted-JSON containment.
    // Terms reach this resolver from every spelling — contains(), raw
    // .filter(col,'cs',…), not(col,'contains'|'matches',…), and .or()
    // string/structured conditions — and only contains() has a method-level
    // guard. Without this check a raw string (e.g. a free-text term ported
    // from a text column, or an .or() condition value, which is always a
    // string) would be storage-encrypted as a JSON SCALAR and silently match
    // nothing; pre-#650 every such spelling failed loudly on capability.
    assertJsonContainmentOperand(column.getName(), term.value)
  }

  // Free-text (bloom) needle floor. A needle shorter than the tokenizer's
  // token_length produces NO tokens, so `bf @> '{}'` holds for every row and
  // the query would silently return (and the caller decrypt) the whole table
  // — a fail-open over-exposure. Reject it up front, mirroring the Drizzle v3
  // adapter (matchNeedleError) so both first-party surfaces guard identically.
  // JSON containment terms (searchableJson) are validated separately above.
  if (queryType === 'freeTextSearch') {
    const match = column.build().indexes?.match
    const reason = match ? matchNeedleError(term.value, match) : undefined
    if (reason) {
      throw new Error(
        `[supabase v3]: cannot search column "${column.getName()}": ${reason}`,
      )
    }
  }

  return column
}

/** One FFI crossing for a column's whole operand list. */
async function bulkEncryptGroup(
  bulkEncrypt: NonNullable<EncryptionClient['bulkEncrypt']>,
  column: V3ColumnLike,
  values: ScalarQueryTerm['value'][],
  ctx: EncryptionContext,
): Promise<Array<Encrypted | null>> {
  const result = await withOpContext(
    bulkEncrypt(
      values.map((plaintext) => ({ plaintext })) as never,
      {
        column,
        table: ctx.table,
      } as never,
    ),
    ctx,
  )
  if (result.failure)
    encryptionFailure(ctx.tableName, result.failure.message, result.failure)

  // `bulkEncrypt` is position-stable, so a length mismatch means the contract
  // was violated. Truncating instead would silently widen an `in` predicate
  // (or narrow a `not.in`) to whatever came back. `result.data` is now
  // `BulkEncryptedData` — `{ id?, data: Encrypted | null }[]` — not `unknown`.
  const encrypted = result.data
  if (encrypted.length !== values.length) {
    encryptionFailure(
      ctx.tableName,
      `bulk encryption returned ${encrypted.length} terms for ${values.length} values on column "${column.getName()}".`,
    )
  }
  return encrypted.map((term, i) => {
    // `BulkEncryptedData` types the element as `Encrypted | null`. A `null`
    // envelope here would be `JSON.stringify`'d to the literal string `"null"`
    // and sent as the filter operand — silently matching whatever `"null"`
    // encodes to rather than failing. A query term should never encrypt to a
    // null envelope, so treat it as a contract violation, not a value.
    if (term.data === null) {
      encryptionFailure(
        ctx.tableName,
        `bulk encryption returned a null envelope at position ${i} for column "${column.getName()}".`,
      )
    }
    return term.data
  })
}

/** Fallback for a client that predates `bulkEncrypt`. */
async function encryptGroupPerTerm(
  column: V3ColumnLike,
  values: ScalarQueryTerm['value'][],
  ctx: EncryptionContext,
): Promise<Encrypted[]> {
  return Promise.all(
    values.map(async (value) => {
      const result = await withOpContext(
        ctx.encryptionClient.encrypt(value, {
          column,
          table: ctx.table,
        }),
        ctx,
      )
      if (result.failure) {
        encryptionFailure(ctx.tableName, result.failure.message, result.failure)
      }
      return result.data
    }),
  )
}
