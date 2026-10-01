/**
 * Rebuild a decrypted plaintext for a date-like model field into a `Date`.
 * Non-date values and already-constructed Dates pass through untouched.
 *
 * The `Number.isNaN` guard is the point of the function, not a formality: an
 * unparseable stored value — a date column written in a non-ISO format, or
 * corrupted — makes `new Date(...)` an Invalid Date. Returning the raw value
 * instead means the caller sees what is actually stored, rather than an
 * Invalid Date whose later `.toISOString()` throws far from the column that
 * produced it (#742 review).
 */
export function reconstructDateValue(value: unknown): unknown {
  if (
    value == null ||
    value instanceof Date ||
    (typeof value !== 'string' && typeof value !== 'number')
  ) {
    return value
  }
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date
}

/** Reconstruct date-like values at dotted model paths without mutating the
 * decrypted input row. Missing paths and non-object intermediates are ignored. */
export function reconstructDatePaths(
  row: Record<string, unknown>,
  paths: readonly string[],
): Record<string, unknown> {
  const out = { ...row }
  for (const path of paths) {
    const segments = path.split('.')
    let source: Record<string, unknown> = row
    let target: Record<string, unknown> = out
    let reachable = true

    for (let i = 0; i < segments.length - 1; i++) {
      const segment = segments[i]
      const sourceChild = source[segment]
      if (
        sourceChild === null ||
        typeof sourceChild !== 'object' ||
        Array.isArray(sourceChild)
      ) {
        reachable = false
        break
      }
      const targetChild = target[segment]
      const cloned = {
        ...((targetChild !== null &&
        typeof targetChild === 'object' &&
        !Array.isArray(targetChild)
          ? targetChild
          : sourceChild) as Record<string, unknown>),
      }
      target[segment] = cloned
      source = sourceChild as Record<string, unknown>
      target = cloned
    }

    const leaf = segments.at(-1)
    if (!reachable || !leaf || !Object.hasOwn(source, leaf)) continue
    target[leaf] = reconstructDateValue(source[leaf])
  }
  return out
}
