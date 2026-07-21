import type { QueryOpName } from '@cipherstash/protect-ffi'
import type {
  BuildableQueryColumn,
  FfiIndexTypeName,
  Plaintext,
  QueryTypeName,
} from '../../types'
import { queryTypeToFfi, queryTypeToQueryOp } from '../../types'

/**
 * Infer the primary index type from a column's configured indexes.
 * Priority: unique > match > ore/ope > ste_vec (for scalar queries; a column
 * carries at most one of `ore`/`ope` — the ordering flavour is pinned by its
 * EQL v3 domain).
 */
export function inferIndexType(column: BuildableQueryColumn): FfiIndexTypeName {
  const config = column.build()
  const indexes = config.indexes

  if (!indexes || Object.keys(indexes).length === 0) {
    throw new Error(`Column "${column.getName()}" has no indexes configured`)
  }

  // Priority order for inference
  if (indexes.unique) return 'unique'
  if (indexes.match) return 'match'
  if (indexes.ore) return 'ore'
  if (indexes.ope) return 'ope'
  if (indexes.ste_vec) return 'ste_vec'

  throw new Error(
    `Column "${column.getName()}" has no suitable index for queries`,
  )
}

/**
 * Infer the FFI query operation from plaintext type for STE Vec queries.
 * - String → ste_vec_selector (JSONPath queries like '$.user.email')
 * - Object/Array/Number/Boolean → default (containment queries)
 */
export function inferQueryOpFromPlaintext(plaintext: Plaintext): QueryOpName {
  if (typeof plaintext === 'string') {
    return 'ste_vec_selector'
  }
  // Objects, arrays, numbers, and booleans use SteVec's default structural
  // containment query. `ste_vec_term` is reserved for selector ordering.
  if (
    typeof plaintext === 'object' ||
    typeof plaintext === 'number' ||
    typeof plaintext === 'boolean'
  ) {
    return 'default'
  }
  // This should never happen with valid JsPlaintext, but keep for safety
  return 'default'
}

/**
 * Validate that the specified index type is configured on the column
 */
export function validateIndexType(
  column: BuildableQueryColumn,
  indexType: FfiIndexTypeName,
): void {
  const config = column.build()
  const indexes = config.indexes ?? {}

  const indexMap: Record<string, boolean> = {
    unique: !!indexes.unique,
    match: !!indexes.match,
    ore: !!indexes.ore,
    ope: !!indexes.ope,
    ste_vec: !!indexes.ste_vec,
  }

  if (!indexMap[indexType]) {
    throw new Error(
      `Index type "${indexType}" is not configured on column "${column.getName()}"`,
    )
  }
}

/**
 * v3-only: an order-capable column answers EQUALITY via its ordering index
 * (`ope`/`op` on `_ord` domains, `ore`/`ob` on `_ord_ore` domains).
 *
 * The v3 capability contract (`src/eql/v3`) documents `equality` as "exact-match
 * lookups (EQL `hm`, or comparison via the ordering term)", so an order-capable
 * column with only an ordering index still supports equality — the
 * equality-vs-range distinction is made by the SQL comparison operator (`=` vs
 * `>=`), NOT by the ciphertext (the FFI emits the same ordering term either
 * way). The default `equality → unique` mapping would wrongly reject these
 * columns. Returns the ordering index to use, or `null` when equality does not
 * resolve through one.
 *
 * Gated on `getQueryCapabilities`, which only v3 queryable columns expose — a v2
 * `EncryptedColumn` lacks it and so never matches, preserving v2's
 * equality-without-unique throw unchanged (the no-v2-change constraint).
 */
function equalityOrderingIndex(
  column: BuildableQueryColumn,
): 'ore' | 'ope' | null {
  if (!('getQueryCapabilities' in column)) return null
  if (!column.getQueryCapabilities().equality) return null
  const indexes = column.build().indexes ?? {}
  if (indexes.unique) return null
  if (indexes.ore) return 'ore'
  if (indexes.ope) return 'ope'
  return null
}

/**
 * Resolve the index type and query operation for a query.
 * Validates the index type is configured on the column when queryType is explicit.
 * For ste_vec columns without explicit queryType, infers queryOp from plaintext shape.
 *
 * @param column - The column to resolve the index type for
 * @param queryType - Optional explicit query type (if provided, validates against column config)
 * @param plaintext - Optional plaintext value for queryOp inference on ste_vec columns
 * @returns The FFI index type name and optional query operation name
 * @throws Error if ste_vec is inferred but queryOp cannot be determined
 */
export function resolveIndexType(
  column: BuildableQueryColumn,
  queryType?: QueryTypeName,
  plaintext?: Plaintext | null,
): { indexType: FfiIndexTypeName; queryOp?: QueryOpName } {
  let indexType = queryType ? queryTypeToFfi[queryType] : inferIndexType(column)

  if (queryType) {
    // An order-capable v3 column answers equality via its ordering index (`op`
    // or `ob`) — the same term `orderAndRange` emits, distinguished only by the
    // SQL `=` operator. Resolve to that index (queryOp undefined) instead of
    // throwing on the missing `unique` index. v2 columns never enter here.
    if (queryType === 'equality') {
      const ordering = equalityOrderingIndex(column)
      if (ordering) return { indexType: ordering }
    }

    // `orderAndRange` maps statically to `ore`; v3 `_ord` domains configure
    // `ope` instead. Swap to the ordering index the column actually carries.
    if (queryType === 'orderAndRange' && indexType === 'ore') {
      const indexes = column.build().indexes ?? {}
      if (!indexes.ore && indexes.ope) indexType = 'ope'
    }

    validateIndexType(column, indexType)

    // For searchableJson, infer queryOp from plaintext type (not from mapping)
    if (queryType === 'searchableJson') {
      if (plaintext === undefined || plaintext === null) {
        return { indexType }
      }
      return { indexType, queryOp: inferQueryOpFromPlaintext(plaintext) }
    }

    return { indexType, queryOp: queryTypeToQueryOp[queryType] }
  }

  // ste_vec inferred without explicit queryType → must infer from plaintext
  if (indexType === 'ste_vec') {
    if (plaintext === undefined || plaintext === null) {
      // Null plaintext handled by caller (returns null early) - no inference needed
      return { indexType }
    }
    return { indexType, queryOp: inferQueryOpFromPlaintext(plaintext) }
  }

  // Non-ste_vec → no queryOp needed
  return { indexType }
}
