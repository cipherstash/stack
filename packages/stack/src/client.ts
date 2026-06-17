/**
 * Client-safe exports for `@cipherstash/stack`.
 *
 * This entry point exports types and utilities that can be used in client-side code
 * without requiring the `@cipherstash/protect-ffi` native module.
 *
 * Use this import path: `@cipherstash/stack/client`
 *
 * `EncryptionClient` is exported as a **type-only** export for use in function
 * signatures without pulling in the native FFI dependency.
 */

export type { EncryptionClient } from '@/encryption'
export type {
  EncryptedColumn,
  EncryptedField,
  EncryptedTable,
  EncryptedTableColumn,
  InferEncrypted,
  InferPlaintext,
} from '@/schema'
// Schema types and utilities - client-safe
export { encryptedColumn, encryptedField, encryptedTable } from '@/schema'
