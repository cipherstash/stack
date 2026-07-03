/**
 * Public type re-exports for `@cipherstash/stack/types`.
 *
 * This module exposes only the public types from the internal types module.
 * Internal helpers (`queryTypeToFfi`, `queryTypeToQueryOp`, `FfiIndexTypeName`,
 * `QueryTermBase`) are excluded.
 */

// Core types
// Client configuration
// Encrypt / decrypt operation options and results
// Model field types
// Bulk operations
// Query types (public only)
export type {
  AuthStrategy,
  BuildableColumn,
  BuildableQueryColumn,
  BuildableTable,
  BuildableTableColumns,
  BuildableV3QueryableColumn,
  BulkDecryptedData,
  BulkDecryptPayload,
  BulkEncryptedData,
  BulkEncryptPayload,
  Client,
  ClientConfig,
  Decrypted,
  DecryptedFields,
  DecryptionResult,
  Encrypted,
  EncryptedFields,
  EncryptedFromBuildableTable,
  EncryptedFromSchema,
  EncryptedQuery,
  EncryptedQueryResult,
  EncryptedReturnType,
  EncryptedSearchTerm,
  EncryptedValue,
  EncryptionClientConfig,
  EncryptOptions,
  EncryptQueryOptions,
  KeysetIdentifier,
  OtherFields,
  QueryTypeName,
  ScalarQueryTerm,
  SearchTerm,
} from '@/types'

// Runtime values
export { queryTypes } from '@/types'
