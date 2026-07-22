import type {
  Encrypted as CipherStashEncrypted,
  EncryptedQuery as CipherStashEncryptedQuery,
  EncryptedV3Query as CipherStashEncryptedV3Query,
  KeysetIdentifier as KeysetIdentifierFfi,
} from '@cipherstash/protect-ffi'
import type { Encrypted, EncryptedQueryResult, KeysetIdentifier } from '@/types'

/**
 * The shape `encryptQuery` / `encryptQueryBulk` can return: a legacy v2 query
 * payload, or a v3 ciphertext-free scalar/SteVec query term (including the
 * bare selector hash and `eql_v3.query_json` containment needle).
 *
 * TODO: replace this local union once `@cipherstash/protect-ffi` exports a
 * named alias for the `encryptQuery` return type
 * (https://github.com/cipherstash/stack/pull/473).
 */
type EncryptedQueryTerm =
  | CipherStashEncrypted
  | CipherStashEncryptedQuery
  | CipherStashEncryptedV3Query

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
 * @example
 * ```typescript
 * const literal = encryptedToCompositeLiteral(encrypted)
 * await supabase.from('table').select().eq('column', literal)
 * ```
 */
export function encryptedToCompositeLiteral(obj: EncryptedQueryTerm): string {
  return `(${JSON.stringify(JSON.stringify(obj))})`
}

/**
 * Helper function to transform an encrypted payload into an escaped PostgreSQL composite literal string.
 * Use this when you need the composite literal format to be escaped as a string value.
 *
 * @example
 * ```typescript
 * const escapedLiteral = encryptedToEscapedCompositeLiteral(encrypted)
 * ```
 */
export function encryptedToEscapedCompositeLiteral(
  obj: EncryptedQueryTerm,
): string {
  return JSON.stringify(encryptedToCompositeLiteral(obj))
}

/**
 * Format an encrypted result based on the requested return type.
 *
 * - `'composite-literal'` → PostgreSQL composite literal string `("json")`
 * - `'escaped-composite-literal'` → escaped variant `"(\"json\")"`
 * - default (`'eql'` or omitted) → raw encrypted object
 */
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
  if (typeof value !== 'object') return false

  const obj = value as Record<string, unknown>

  // Must have version field (number)
  if (!('v' in obj) || typeof obj.v !== 'number') return false

  // Must have index field (object)
  if (!('i' in obj) || typeof obj.i !== 'object') return false

  // Must have either ciphertext (c) or searchable vector (sv)
  if (!('c' in obj) && !('sv' in obj)) return false

  return true
}

export {
  buildNestedObject,
  parseJsonbPath,
  toJsonPath,
} from './jsonb'
