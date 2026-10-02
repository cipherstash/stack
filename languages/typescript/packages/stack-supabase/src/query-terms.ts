import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { QueryTypeName, ScalarQueryTerm } from '@cipherstash/stack/types'
import type { V3ColumnLike } from './column-map'
import {
  isEncryptableTerm,
  isEncryptedColumn,
  mapFilterOpToQueryType,
} from './helpers'
import type { EncryptionContext } from './query-encrypt'
import type { DbQuerySpace, FilterOp } from './types'

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

export type CollectedQueryTerm = {
  value: ScalarQueryTerm['value']
  column: V3ColumnLike
  table: AnyV3Table
  queryType?: QueryTypeName
  returnType?: ScalarQueryTerm['returnType']
}

/**
 * Resolve a raw `.filter()` operator to the capability it exercises. A
 * supported v3 operand is a full storage envelope, so `queryType` never
 * selects a narrowing — it only tells `assertTermQueryable` which capability
 * to demand of the column.
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

/** A nullish encrypted search operand is never a SQL-NULL predicate. Skipping
 * encryption would put the raw operand on the wire under `cs`, so fail closed
 * for every spelling (`matches`, `contains`, raw `cs`, `not`, and `.or()`). */
function assertEncryptedSearchOperand(
  queryType: QueryTypeName,
  value: unknown,
  column: string,
): void {
  if (
    value == null &&
    (queryType === 'freeTextSearch' || queryType === 'searchableJson')
  ) {
    throw new Error(
      `[supabase v3]: encrypted search on column "${column}" requires a non-null operand; null and undefined cannot be sent through the plaintext PostgREST filter path.`,
    )
  }
}

/**
 * Walk a `DbQuerySpace` and collect every operand that must be encrypted,
 * paired with the mapping that puts each result back where it came from.
 *
 * Pure and synchronous: no FFI crossing happens here. Capability validation is
 * deliberately NOT done on this pass — `assertTermQueryable` is the single
 * boundary for that, so every spelling collected below is checked identically
 * rather than once per loop.
 */
export function collectQueryTerms(
  dbSpace: DbQuerySpace,
  ctx: Pick<EncryptionContext, 'table' | 'columns'>,
): { terms: CollectedQueryTerm[]; termMap: TermMapping[] } {
  const terms: CollectedQueryTerm[] = []
  const termMap: TermMapping[] = []

  const tableColumns = ctx.columns.queryColumnMap()
  const encryptedColumnNames = ctx.columns.encryptedColumnNames

  const pushTerm = (
    value: JsPlaintext,
    column: V3ColumnLike,
    queryType: QueryTypeName,
    mapping: TermMapping,
  ) => {
    terms.push({
      value,
      column,
      table: ctx.table,
      queryType,
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
    column: V3ColumnLike,
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
    const queryType = mapFilterOpToQueryType(f.op)
    assertEncryptedSearchOperand(queryType, f.value, f.column)

    if (f.op === 'in' && Array.isArray(f.value)) {
      collectInListTerms(f.op, f.value, column, queryType, (inIndex) => ({
        source: 'filter',
        filterIndex: i,
        inIndex,
      }))
    } else if (!isEncryptableTerm(f.op, f.value)) {
      // `is` predicate or null operand — forwarded unencrypted.
    } else {
      pushTerm(f.value as JsPlaintext, column, queryType, {
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
    const column = tableColumns[nf.column]
    if (!column) continue
    const queryType = mapFilterOpToQueryType(nf.op)
    assertEncryptedSearchOperand(queryType, nf.value, nf.column)
    if (!isEncryptableTerm(nf.op, nf.value)) continue

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
      collectInListTerms(nf.op, nf.value, column, queryType, (inIndex) => ({
        source: 'not',
        notIndex: i,
        inIndex,
      }))
      continue
    }

    pushTerm(nf.value as JsPlaintext, column, queryType, {
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
      assertEncryptedSearchOperand(queryType, cond.value, cond.column)
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
    const queryType = queryTypeForRawOp(rf.operator)
    assertEncryptedSearchOperand(queryType, rf.value, rf.column)

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
      collectInListTerms('in', rf.value, column, queryType, (inIndex) => ({
        source: 'raw',
        rawIndex: i,
        inIndex,
      }))
      continue
    }

    if (!isEncryptableTerm(rf.operator, rf.value)) continue

    pushTerm(rf.value as JsPlaintext, column, queryType, {
      source: 'raw',
      rawIndex: i,
    })
  }

  return { terms, termMap }
}
