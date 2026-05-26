import type {
  Encrypted as CipherStashEncrypted,
  EncryptedQuery as CipherStashEncryptedQuery,
  EncryptedScalarQuery,
  KeysetIdentifier as KeysetIdentifierFfi,
} from '@cipherstash/protect-ffi'
import type {
  Encrypted,
  EncryptedQueryResult,
  KeysetIdentifier,
} from '../types'

/**
 * The shape `encryptQuery` / `encryptQueryBulk` can return: a full storage
 * payload (`Encrypted`, returned for `ste_vec_term` containment queries) or a
 * query-only payload with no ciphertext (`EncryptedQuery`, returned for
 * scalar `unique`/`match`/`ore` lookups and `ste_vec_selector` path queries).
 *
 * TODO: duplicated in `@cipherstash/stack` — see
 * `packages/stack/src/encryption/helpers/index.ts`. Both copies should be
 * removed once `@cipherstash/protect-ffi` exports a named alias for the
 * `encryptQuery` return type (https://github.com/cipherstash/stack/pull/473).
 */
type EncryptedQueryTerm = CipherStashEncrypted | CipherStashEncryptedQuery

export type EncryptedPgComposite = {
  data: Encrypted
}

/**
 * Helper function to transform an encrypted payload into a PostgreSQL composite type.
 * Use this when inserting data via Supabase or similar clients.
 */
export function encryptedToPgComposite(obj: Encrypted): EncryptedPgComposite {
  return {
    data: obj,
  }
}

/**
 * Helper function to transform an encrypted payload into a PostgreSQL composite literal string.
 * Use this when querying with `.eq()` or similar equality operations in Supabase.
 *
 * @deprecated Use `encryptQuery()` with `returnType: 'composite-literal'` instead.
 * @example
 * ```typescript
 * // Before (deprecated):
 * const [encrypted] = await protectClient.encryptQuery([
 *   { value: searchValue, column, table, queryType: 'equality' }
 * ])
 * const literal = encryptedToCompositeLiteral(encrypted)
 * await supabase.from('table').select().eq('column', literal)
 *
 * // After (recommended):
 * const [searchTerm] = await protectClient.encryptQuery([
 *   { value: searchValue, column, table, queryType: 'equality', returnType: 'composite-literal' }
 * ])
 * await supabase.from('table').select().eq('column', searchTerm)
 * ```
 */
export function encryptedToCompositeLiteral(obj: EncryptedQueryTerm): string {
  if (obj === null) {
    throw new Error('encryptedToCompositeLiteral: obj cannot be null')
  }
  return `(${JSON.stringify(JSON.stringify(obj))})`
}

/**
 * Helper function to transform an encrypted payload into an escaped PostgreSQL composite literal string.
 * Use this when you need the composite literal format to be escaped as a string value.
 *
 * @deprecated Use `encryptQuery()` with `returnType: 'escaped-composite-literal'` instead.
 * See also: `encryptedToCompositeLiteral` for parallel deprecation guidance.
 * @example
 * ```typescript
 * // Before (deprecated):
 * const [encrypted] = await protectClient.encryptQuery([
 *   { value: searchValue, column, table, queryType: 'equality' }
 * ])
 * const escapedLiteral = encryptedToEscapedCompositeLiteral(encrypted)
 *
 * // After (recommended):
 * const [searchTerm] = await protectClient.encryptQuery([
 *   { value: searchValue, column, table, queryType: 'equality', returnType: 'escaped-composite-literal' }
 * ])
 * ```
 */
export function encryptedToEscapedCompositeLiteral(
  obj: EncryptedQueryTerm,
): string {
  if (obj === null) {
    throw new Error('encryptedToEscapedCompositeLiteral: obj cannot be null')
  }
  return JSON.stringify(encryptedToCompositeLiteral(obj))
}

export function formatEncryptedResult(
  encrypted: EncryptedQueryTerm,
  returnType?: string,
): EncryptedQueryResult {
  if (returnType === 'composite-literal') {
    return encryptedToCompositeLiteral(encrypted)
  }
  if (returnType === 'escaped-composite-literal') {
    return encryptedToEscapedCompositeLiteral(encrypted)
  }
  return encrypted
}

/**
 * Helper function to transform a model's encrypted fields into PostgreSQL composite types
 */
export function modelToEncryptedPgComposites<T extends Record<string, unknown>>(
  model: T,
): T {
  const result: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(model)) {
    if (isEncryptedPayload(value)) {
      result[key] = encryptedToPgComposite(value)
    } else {
      result[key] = value
    }
  }

  return result as T
}

/**
 * Helper function to transform multiple models' encrypted fields into PostgreSQL composite types
 */
export function bulkModelsToEncryptedPgComposites<
  T extends Record<string, unknown>,
>(models: T[]): T[] {
  return models.map((model) => modelToEncryptedPgComposites(model))
}

export function toFfiKeysetIdentifier(
  keyset: KeysetIdentifier | undefined,
): KeysetIdentifierFfi | undefined {
  if (!keyset) return undefined

  if ('name' in keyset) {
    return { Name: keyset.name }
  }

  return { Uuid: keyset.id }
}

/**
 * Helper function to check if a value is an encrypted payload
 */
export function isEncryptedPayload(value: unknown): value is Encrypted {
  if (value === null) return false

  // TODO: this can definitely be improved
  if (typeof value === 'object') {
    const obj = value as Encrypted
    return (
      obj !== null && 'v' in obj && ('c' in obj || 'sv' in obj) && 'i' in obj
    )
  }

  return false
}

/**
 * Type guard narrowing a value to {@link EncryptedScalarQuery} — the scalar
 * query term (`unique` / `match` / `ore` lookup) returned by `encryptQuery` /
 * `encryptQueryBulk`. Unlike a storage payload it carries no ciphertext (`c`);
 * it carries exactly one lookup term: `hm`, `bf`, or `ob`.
 *
 * Use this to discriminate a scalar query term from a storage payload
 * (`EncryptedScalar`/`EncryptedSteVec`) or a `ste_vec_selector` query.
 */
export function isEncryptedScalarQuery(
  value: unknown,
): value is EncryptedScalarQuery {
  if (value === null || typeof value !== 'object') return false

  const obj = value as Record<string, unknown>

  // `k: 'ct'` is the scalar discriminant; a query term never carries the
  // ciphertext (`c`) that every storage payload has.
  if (obj.k !== 'ct' || 'c' in obj) return false
  if (
    typeof obj.v !== 'number' ||
    typeof obj.i !== 'object' ||
    obj.i === null
  ) {
    return false
  }

  // Exactly one lookup term: `hm` (unique), `bf` (match), or `ob` (ore).
  const lookupTerms = [
    typeof obj.hm === 'string',
    Array.isArray(obj.bf),
    Array.isArray(obj.ob),
  ].filter(Boolean)
  return lookupTerms.length === 1
}

export {
  toJsonPath,
  buildNestedObject,
  parseJsonbPath,
} from './jsonb'
