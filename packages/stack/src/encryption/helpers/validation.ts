import type { Result } from '@byteslice/result'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { FfiIndexTypeName } from '@/types'

/**
 * Inclusive bounds of a signed 64-bit integer (`int8`) — the range every
 * `bigint` domain (`public.bigint`, `bigint_eq`, `bigint_ord_ore`,
 * `bigint_ord`) maps to on the Postgres side. A `bigint` outside this range
 * cannot be expressed as an `int8`, so it must be rejected before it reaches
 * protect-ffi (whose behaviour on an out-of-range value is unobservable here).
 * This is the `bigint` analog of the NaN/±Infinity guard for `number` domains:
 * a deterministic, client-side rejection of a plaintext the target type cannot
 * hold.
 */
const INT64_MIN = -9223372036854775808n
const INT64_MAX = 9223372036854775807n

/** True when `value` is a `bigint` outside the signed 64-bit range. */
function isBigintOutOfInt64Range(value: unknown): value is bigint {
  return typeof value === 'bigint' && (value < INT64_MIN || value > INT64_MAX)
}

/**
 * Validates that a value is not NaN/Infinity and, for `bigint`, is within the
 * signed 64-bit (`int8`) range.
 * Returns a failure Result if validation fails, undefined otherwise.
 * Use this in async flows that return Result types.
 *
 * Uses `never` as the success type so the result can be assigned to any Result<T, EncryptionError>.
 *
 * @internal
 */
export function validateNumericValue(
  value: unknown,
): Result<never, EncryptionError> | undefined {
  if (typeof value === 'number' && Number.isNaN(value)) {
    return {
      failure: {
        type: EncryptionErrorTypes.EncryptionError,
        message: '[encryption]: Cannot encrypt NaN value',
      },
    }
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    return {
      failure: {
        type: EncryptionErrorTypes.EncryptionError,
        message: '[encryption]: Cannot encrypt Infinity value',
      },
    }
  }
  if (isBigintOutOfInt64Range(value)) {
    return {
      failure: {
        type: EncryptionErrorTypes.EncryptionError,
        message: '[encryption]: Cannot encrypt bigint value out of int64 range',
      },
    }
  }
  return undefined
}

/**
 * Validates that a value is not NaN/Infinity and, for `bigint`, is within the
 * signed 64-bit (`int8`) range.
 * Throws an error if validation fails.
 * Use this in sync flows where exceptions are caught.
 *
 * @internal
 */
export function assertValidNumericValue(value: unknown): void {
  if (typeof value === 'number' && Number.isNaN(value)) {
    throw new Error('[encryption]: Cannot encrypt NaN value')
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('[encryption]: Cannot encrypt Infinity value')
  }
  if (isBigintOutOfInt64Range(value)) {
    throw new Error(
      '[encryption]: Cannot encrypt bigint value out of int64 range',
    )
  }
}

/**
 * Validates that the value type is compatible with the index type.
 * Match index (freeTextSearch) only supports string values.
 * Returns a failure Result if validation fails, undefined otherwise.
 * Use this in async flows that return Result types.
 *
 * @internal
 */
export function validateValueIndexCompatibility(
  value: unknown,
  indexType: FfiIndexTypeName,
  columnName: string,
): Result<never, EncryptionError> | undefined {
  if (
    (typeof value === 'number' || typeof value === 'bigint') &&
    indexType === 'match'
  ) {
    return {
      failure: {
        type: EncryptionErrorTypes.EncryptionError,
        message: `[encryption]: Cannot use 'match' index with numeric value on column "${columnName}". The 'freeTextSearch' index only supports string values. Configure the column with 'orderAndRange()' or 'equality()' for numeric queries.`,
      },
    }
  }
  return undefined
}

/**
 * Validates that the value type is compatible with the index type.
 * Match index (freeTextSearch) only supports string values.
 * Throws an error if validation fails.
 * Use this in sync flows where exceptions are caught.
 *
 * @internal
 */
export function assertValueIndexCompatibility(
  value: unknown,
  indexType: FfiIndexTypeName,
  columnName: string,
): void {
  if (
    (typeof value === 'number' || typeof value === 'bigint') &&
    indexType === 'match'
  ) {
    throw new Error(
      `[encryption]: Cannot use 'match' index with numeric value on column "${columnName}". The 'freeTextSearch' index only supports string values. Configure the column with 'orderAndRange()' or 'equality()' for numeric queries.`,
    )
  }
}
