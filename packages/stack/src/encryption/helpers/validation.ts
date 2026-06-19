import type { Result } from '@byteslice/result'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { FfiIndexTypeName } from '@/types'

/**
 * Validates that a value is not NaN or Infinity.
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
  return undefined
}

/**
 * Validates that a value is not NaN or Infinity.
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
  if (typeof value === 'number' && indexType === 'match') {
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
  if (typeof value === 'number' && indexType === 'match') {
    throw new Error(
      `[encryption]: Cannot use 'match' index with numeric value on column "${columnName}". The 'freeTextSearch' index only supports string values. Configure the column with 'orderAndRange()' or 'equality()' for numeric queries.`,
    )
  }
}
