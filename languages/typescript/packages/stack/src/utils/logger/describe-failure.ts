// Type-only imports: adapter-kit must stay importable without loading the
// native binding or the auth module, so the allowlists below are written out
// as `Record`s over the code unions, which makes the compiler prove them
// complete.
import type { AuthErrorCode } from '@cipherstash/auth'
import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import { EncryptionErrorTypes } from '@/errors'

/**
 * A log-safe description of a failure, for an adapter's error log.
 *
 * An adapter's catch sees errors from every layer below it (query validation,
 * encryption, the database client, the network), and any of their messages may
 * quote a plaintext value. The library promises never to log plaintext, so an
 * error log names the failure's KIND, never its message.
 *
 * Everything in the result comes from a fixed allowlist, never from the error:
 *
 * - the error class, when it is a built-in JS error or one of this library's
 *   error classes, else `Error` (or `typeof` for a non-Error value);
 * - the error's `type`, `code` and `authCode`, and those of a nested
 *   `encryptionError` (the Supabase adapter's `EncryptionFailedError`), when
 *   each is a known {@link EncryptionErrorTypes} value, FFI error code
 *   (`PROTECT_ERROR_CODES`) or auth code (`AuthErrorCode`).
 *
 * Any other value is dropped, however harmless it looks: a field that merely
 * looks like an identifier can still hold caller data. If reading the error
 * throws (a throwing getter, a revoked proxy), the result is `unknown failure`,
 * so describing a failure never becomes a second failure.
 *
 * @example
 *   describeFailure(new TypeError('value "x" is bad'))       // 'TypeError'
 *   describeFailure(Object.assign(new Error('…'), { code: 'UNKNOWN_COLUMN' }))
 *   // 'Error: UNKNOWN_COLUMN'
 */
export function describeFailure(err: unknown): string {
  try {
    const ids = [
      ...identifiersOf(err),
      ...identifiersOf(fieldOf(err, 'encryptionError')),
    ]
    return [kindOf(err), ...new Set(ids)].join(': ')
  } catch {
    return 'unknown failure'
  }
}

// Any other name is reported as plain `Error`.
const ERROR_CLASSES: ReadonlySet<string> = new Set([
  'AggregateError',
  'EvalError',
  'RangeError',
  'ReferenceError',
  'SyntaxError',
  'TypeError',
  'URIError',
  // This library's own error classes.
  'EncryptedDynamoDBError',
  'EncryptionFailedError',
])

// A `Record` over each union, so the compiler rejects a missing or unknown code.
const FFI_ERROR_CODES: Record<ProtectErrorCode, true> = {
  INVARIANT_VIOLATION: true,
  UNKNOWN_QUERY_OP: true,
  UNKNOWN_COLUMN: true,
  MISSING_INDEX: true,
  INVALID_QUERY_INPUT: true,
  SHORT_MATCH_NEEDLE: true,
  INVALID_JSON_PATH: true,
  STE_VEC_REQUIRES_JSON_CAST_AS: true,
  MATCH_REQUIRES_TEXT: true,
  UNSUPPORTED_CONFIG_VERSION: true,
  INVALID_EQL_VERSION: true,
  EQL_V3_UNSUPPORTED_COLUMN: true,
  EQL_V3_CONVERSION_FAILED: true,
  INVALID_CIPHERTEXT: true,
  UNKNOWN: true,
}

const AUTH_ERROR_CODES: Record<AuthErrorCode, true> = {
  REQUEST_ERROR: true,
  ACCESS_DENIED: true,
  EXPIRED_TOKEN: true,
  INVALID_GRANT: true,
  INVALID_CLIENT: true,
  INVALID_URL: true,
  INVALID_REGION: true,
  INVALID_TOKEN: true,
  USAGE_LIMIT_EXCEEDED: true,
  ORG_NOT_PROVISIONED: true,
  SERVER_ERROR: true,
  NOT_AUTHENTICATED: true,
  MISSING_WORKSPACE_CRN: true,
  INVALID_ACCESS_KEY: true,
  INVALID_CRN: true,
  WORKSPACE_MISMATCH: true,
  INVALID_WORKSPACE_ID: true,
  ALREADY_CONSUMED: true,
  INTERNAL_ERROR: true,
  CUSTOM: true,
  STORE_ERROR: true,
}

const KNOWN_IDENTIFIERS: ReadonlySet<string> = new Set([
  ...Object.values(EncryptionErrorTypes),
  ...Object.keys(FFI_ERROR_CODES),
  ...Object.keys(AUTH_ERROR_CODES),
])

function kindOf(err: unknown): string {
  if (err instanceof Error) {
    return ERROR_CLASSES.has(err.name) ? err.name : 'Error'
  }
  return err === null ? 'null' : typeof err
}

function fieldOf(value: unknown, key: string): unknown {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)[key]
    : undefined
}

function identifiersOf(value: unknown): string[] {
  return (['type', 'code', 'authCode'] as const)
    .map((key) => fieldOf(value, key))
    .filter(
      (id): id is string => typeof id === 'string' && KNOWN_IDENTIFIERS.has(id),
    )
}
