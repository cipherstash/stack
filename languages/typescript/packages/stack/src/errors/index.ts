import type {
  ProtectAuthErrorCode,
  ProtectErrorCode,
} from '@cipherstash/protect-ffi'

// `as const` is load-bearing: without it every member's type widens to `string`,
// so the `type` fields on the StackError union members below all become `string`
// and the union stops discriminating — `switch (error.type)` cannot narrow, and
// the documented exhaustive error-handling pattern fails to compile.
export const EncryptionErrorTypes = {
  ClientInitError: 'ClientInitError',
  EncryptionError: 'EncryptionError',
  DecryptionError: 'DecryptionError',
  LockContextError: 'LockContextError',
  CtsTokenError: 'CtsTokenError',
} as const

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
  /**
   * The auth taxonomy code, present only when CipherStash's token service
   * refused to issue or renew the service token behind the operation.
   *
   * Set for a failure that is neither transient nor a credentials problem, and
   * that `type` cannot express — `USAGE_LIMIT_EXCEEDED` above all, which means
   * the organisation is over its billing allowance and no amount of retrying
   * or key rotation will clear it. {@link EncryptionError.help} and
   * {@link EncryptionError.url} carry the upstream remedy. This field is for
   * branching on the condition.
   *
   * ```typescript
   * if (result.failure?.authCode === 'USAGE_LIMIT_EXCEEDED') {
   *   // stop retrying; surface the billing state to an operator
   * }
   * ```
   *
   * Open by design — the set is owned by `@cipherstash/auth` and versioned on
   * its own release train, so compare with `===` rather than switching
   * exhaustively.
   */
  authCode?: ProtectAuthErrorCode
  /**
   * The remedy text the underlying failure carried, verbatim.
   *
   * Kept separate from `message` so callers can render diagnosis and guidance
   * in different places.
   *
   * Absent for a failure whose source attached no remedy — most of them.
   */
  help?: string
  /**
   * A URL with more on this failure, when the underlying failure carried one.
   *
   * The sibling of {@link help} on the same `miette` diagnostic surface: both
   * are dropped by an error's `Display`, so both reach JS only as fields.
   * Absent far more often than present.
   */
  url?: string
}

// ---------------------------------------------------------------------------
// Specific error types (discriminated union members)
// ---------------------------------------------------------------------------

export interface ClientInitError {
  type: typeof EncryptionErrorTypes.ClientInitError
  message: string
  code?: ProtectErrorCode
  /** @see {@link EncryptionError.authCode} */
  authCode?: ProtectAuthErrorCode
  /**
   * The remedy text the underlying error carried, verbatim.
   *
   * `Encryption()` throws rather than returning a `Result`, so this structured
   * field lets callers render guidance separately from the diagnosis.
   *
   * Absent for a failure whose source attached no help — most of them.
   */
  help?: string
  /**
   * A URL with more on this failure, when the underlying error carried one.
   *
   * The sibling of {@link help} on the same diagnostic surface — `miette`
   * exposes both, and both are dropped by an error's `Display`. Absent far more
   * often than present; do not treat it as the remedy.
   */
  url?: string
}

export interface EncryptionOperationError {
  type: typeof EncryptionErrorTypes.EncryptionError
  message: string
  code?: ProtectErrorCode
  /** @see {@link EncryptionError.authCode} */
  authCode?: ProtectAuthErrorCode
  /** @see {@link EncryptionError.help} */
  help?: string
  /** @see {@link EncryptionError.url} */
  url?: string
}

export interface DecryptionOperationError {
  type: typeof EncryptionErrorTypes.DecryptionError
  message: string
  code?: ProtectErrorCode
  /** @see {@link EncryptionError.authCode} */
  authCode?: ProtectAuthErrorCode
  /** @see {@link EncryptionError.help} */
  help?: string
  /** @see {@link EncryptionError.url} */
  url?: string
}

export interface LockContextError {
  type: typeof EncryptionErrorTypes.LockContextError
  message: string
}

export interface CtsTokenError {
  type: typeof EncryptionErrorTypes.CtsTokenError
  message: string
  /**
   * Set when CipherStash's token service refused the request outright, rather
   * than the request failing to reach it.
   *
   * `LockContext.identify()` is the one place in this package that calls CTS
   * over HTTP itself, so it is the one place a refusal has to be read off a
   * response instead of arriving on a thrown protect-ffi error. The values are
   * the same taxonomy — `USAGE_LIMIT_EXCEEDED` above all.
   *
   * @see {@link EncryptionError.authCode}
   */
  authCode?: ProtectAuthErrorCode
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
