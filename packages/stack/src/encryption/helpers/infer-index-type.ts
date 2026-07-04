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
 * Priority: unique > match > ore > ste_vec (for scalar queries)
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
  if (indexes.ste_vec) return 'ste_vec'

  throw new Error(
    `Column "${column.getName()}" has no suitable index for queries`,
  )
}

/**
 * Infer the FFI query operation from plaintext type for STE Vec queries.
 * - String → ste_vec_selector (JSONPath queries like '$.user.email')
 * - Object/Array/Number/Boolean → ste_vec_term (containment queries)
 */
export function inferQueryOpFromPlaintext(plaintext: Plaintext): QueryOpName {
  if (typeof plaintext === 'string') {
    return 'ste_vec_selector'
  }
  // Objects (incl. Date), arrays, numbers, booleans are all valid JSONB
  // containment values
  if (
    typeof plaintext === 'object' ||
    typeof plaintext === 'number' ||
    typeof plaintext === 'boolean'
  ) {
    return 'ste_vec_term'
  }
  // This should never happen with valid JsPlaintext, but keep for safety
  return 'ste_vec_term'
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
    ste_vec: !!indexes.ste_vec,
  }

  if (!indexMap[indexType]) {
    throw new Error(
      `Index type "${indexType}" is not configured on column "${column.getName()}"`,
    )
  }
}

/**
 * v3-only: an order-capable column answers EQUALITY via its `ore` (`ob`) index.
 *
 * The v3 capability contract (`src/eql/v3`) documents `equality` as "exact-match
 * lookups (EQL `hm`, or comparison via `ob`)", so an order-capable column with only
 * an `ore` index still supports equality — the equality-vs-range distinction is made
 * by the SQL comparison operator (`=` vs `>=`), NOT by the ciphertext (the FFI emits
 * the same `ob` term either way). The default `equality → unique` mapping would
 * wrongly reject these columns.
 *
 * Gated on `getQueryCapabilities`, which only v3 queryable columns expose — a v2
 * `EncryptedColumn` lacks it and so never matches, preserving v2's
 * equality-without-unique throw unchanged (the no-v2-change constraint).
 */
function resolvesEqualityViaOre(column: BuildableQueryColumn): boolean {
  if (!('getQueryCapabilities' in column)) return false
  if (!column.getQueryCapabilities().equality) return false
  const indexes = column.build().indexes ?? {}
  return !indexes.unique && !!indexes.ore
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
  const indexType = queryType
    ? queryTypeToFfi[queryType]
    : inferIndexType(column)

  if (queryType) {
    // An order-capable v3 column answers equality via its `ore` index (`ob`
    // term) — the same term `orderAndRange` emits, distinguished only by the SQL
    // `=` operator. Resolve to `ore` (queryOp undefined) instead of throwing on
    // the missing `unique` index. v2 columns never enter here (see helper).
    if (queryType === 'equality' && resolvesEqualityViaOre(column)) {
      return { indexType: 'ore' }
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
