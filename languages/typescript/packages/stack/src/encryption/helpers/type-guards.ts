import type { ScalarQueryTerm } from '../../types'

/**
 * Type guard to check if a value is an array of ScalarQueryTerm objects.
 * Used to discriminate between single value and bulk encryption in encryptQuery overloads.
 */
export function isScalarQueryTermArray(
  value: unknown,
): value is readonly ScalarQueryTerm[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    typeof value[0] === 'object' &&
    value[0] !== null &&
    'column' in value[0] &&
    'table' in value[0]
  )
}
