/**
 * Public type re-exports for `@cipherstash/stack/types`.
 *
 * This module exposes only the public types from the internal types module.
 * Internal helpers (`queryTypeToFfi`, `queryTypeToQueryOp`, `FfiIndexTypeName`,
 * `QueryTermBase`) are excluded.
 */

// Core types
export type {
  Client,
  EncryptedValue,
  Encrypted,
  EncryptedQuery,
} from '@/types'

// Client configuration
export type {
  KeysetIdentifier,
  ClientConfig,
  EncryptionClientConfig,
} from '@/types'

// Encrypt / decrypt operation options and results
export type {
  EncryptOptions,
  EncryptedReturnType,
  SearchTerm,
  EncryptedSearchTerm,
  EncryptedQueryResult,
} from '@/types'

// Model field types
export type {
  EncryptedFields,
  OtherFields,
  DecryptedFields,
  Decrypted,
  EncryptedFromSchema,
} from '@/types'

// Bulk operations
export type {
  BulkEncryptPayload,
  BulkEncryptedData,
  BulkDecryptPayload,
  BulkDecryptedData,
  DecryptionResult,
} from '@/types'

// Query types (public only)
export type {
  QueryTypeName,
  EncryptQueryOptions,
  ScalarQueryTerm,
} from '@/types'

// Runtime values
export { queryTypes } from '@/types'
