/**
 * Client-safe exports for @cipherstash/protect
 *
 * This entry point exports types and utilities that can be used in client-side code
 * without requiring the @cipherstash/protect-ffi native module.
 *
 * Use this import path: `@cipherstash/protect/client`
 */

export type {
  ProtectColumn,
  ProtectTable,
  ProtectTableColumn,
  ProtectValue,
} from '@cipherstash/schema'
// Schema types and utilities - client-safe
export { csColumn, csTable, csValue } from '@cipherstash/schema'
export type { ProtectClient } from './ffi'
