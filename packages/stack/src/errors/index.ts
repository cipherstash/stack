import type { ProtectErrorCode } from '@cipherstash/protect-ffi'

export const EncryptionErrorTypes = {
  ClientInitError: 'ClientInitError',
  EncryptionError: 'EncryptionError',
  DecryptionError: 'DecryptionError',
  LockContextError: 'LockContextError',
  CtsTokenError: 'CtsTokenError',
}

/**
 * Base error interface returned by all encryption operations.
 *
 * Every operation that can fail returns `Result<T, EncryptionError>`.
 * Use the `type` field to narrow to a specific error kind, or use
 * {@link StackError} for an exhaustive discriminated union.
 *
 * @example
 * ```typescript
 * const result = await client.encrypt(value, opts)
 * if (result.failure) {
 *   switch (result.failure.type) {
 *     case EncryptionErrorTypes.EncryptionError:
 *       console.error('Encryption failed:', result.failure.message)
 *       break
 *     case EncryptionErrorTypes.LockContextError:
 *       console.error('Lock context issue:', result.failure.message)
 *       break
 *   }
 * }
 * ```
 */
export interface EncryptionError {
  type: (typeof EncryptionErrorTypes)[keyof typeof EncryptionErrorTypes]
  message: string
  code?: ProtectErrorCode
  // `@byteslice/result` 0.5 requires a failure to be an `Error` or to carry an
  // `error: Error`. Hold the originating error here so the structured
  // `type`/`message`/`code` fields stay available to callers that narrow on
  // them. Build via {@link toEncryptionError} so this is always a real `Error`.
  error: Error
}

// ---------------------------------------------------------------------------
// Specific error types (discriminated union members)
// ---------------------------------------------------------------------------

export interface ClientInitError {
  type: typeof EncryptionErrorTypes.ClientInitError
  message: string
}

export interface EncryptionOperationError {
  type: typeof EncryptionErrorTypes.EncryptionError
  message: string
  code?: ProtectErrorCode
}

export interface DecryptionOperationError {
  type: typeof EncryptionErrorTypes.DecryptionError
  message: string
  code?: ProtectErrorCode
}

export interface LockContextError {
  type: typeof EncryptionErrorTypes.LockContextError
  message: string
}

export interface CtsTokenError {
  type: typeof EncryptionErrorTypes.CtsTokenError
  message: string
}

/**
 * Discriminated union of all specific error types.
 *
 * Use `StackError` when you need exhaustive error handling via `switch` on the `type` field.
 *
 * @example
 * ```typescript
 * function handleError(error: StackError) {
 *   switch (error.type) {
 *     case 'ClientInitError':
 *       // re-initialize client
 *       break
 *     case 'EncryptionError':
 *     case 'DecryptionError':
 *       // log and retry
 *       break
 *     case 'LockContextError':
 *       // re-authenticate
 *       break
 *     case 'CtsTokenError':
 *       // refresh token
 *       break
 *     default:
 *       error satisfies never
 *   }
 * }
 * ```
 */
export type StackError =
  | ClientInitError
  | EncryptionOperationError
  | DecryptionOperationError
  | LockContextError
  | CtsTokenError

// ---------------------------------------------------------------------------
// Error utilities
// ---------------------------------------------------------------------------

/**
 * Safely extract an error message from an unknown thrown value.
 * Unlike `(error as Error).message`, this handles non-Error values gracefully.
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === 'string') return error
  return String(error)
}

/**
 * Build an {@link EncryptionError} from a caught value.
 *
 * `@byteslice/result` 0.5 requires a failure to be an `Error` or to carry an
 * `error: Error`, so this coerces an arbitrary caught value to a real `Error`
 * (never a lie) and derives `message` from it, while preserving the structured
 * `type` and optional `code` fields callers narrow on. Pass a `new Error(...)`
 * for failures that have no underlying caught error (e.g. validation).
 */
export function toEncryptionError(
  type: EncryptionError['type'],
  error: unknown,
  code?: ProtectErrorCode,
): EncryptionError {
  const err = error instanceof Error ? error : new Error(getErrorMessage(error))
  return code === undefined
    ? { type, message: err.message, error: err }
    : { type, message: err.message, code, error: err }
}
