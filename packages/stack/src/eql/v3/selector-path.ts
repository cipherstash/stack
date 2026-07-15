/**
 * Shared JSONPath-selector path handling for the first-party adapters
 * (`@cipherstash/stack-drizzle`, `@cipherstash/stack-supabase`), exposed via
 * `@cipherstash/stack/adapter-kit`.
 *
 * Both adapters express "compare the value at `$.a.b`" over an encrypted
 * `eql_v3_json` column, and both need the same three pieces: parse + validate
 * the dot-notation path, reconstruct the `{ a: { b: value } }` needle document
 * whose ste_vec entry at the path carries the comparison terms, and reject
 * non-scalar leaves up front. Originally private to the Drizzle v3 operators
 * (#651); moved here when the Supabase adapter grew the same querying (#650) so
 * the validation rules cannot drift between adapters.
 */

/**
 * Object keys that are prototype-pollution vectors — rejected outright (mirrors
 * core's `FORBIDDEN_KEYS`), so a selector can never address them.
 */
const FORBIDDEN_SEGMENTS: ReadonlySet<string> = new Set([
  '__proto__',
  'prototype',
  'constructor',
])

/**
 * Parse a dot-notation JSONPath into its object-key segments. Rejects, each with
 * a clear message: array-index/wildcard syntax (v1 is object-keys-only), the
 * empty/root path, malformed paths (`..`, stray/leading/trailing dots, so we
 * never silently query a *different* path), and prototype-pollution keys.
 * `'$.a.b'` / `' a.b '` → `['a', 'b']`.
 */
export function parseSelectorSegments(path: string): string[] {
  const trimmed = path.trim()
  let body = trimmed.startsWith('$') ? trimmed.slice(1) : trimmed
  if (body.startsWith('.')) body = body.slice(1)
  if (body === '') {
    throw new Error(
      `JSON selector path "${path}" addresses no field — use e.g. "$.a" or "$.a.b".`,
    )
  }
  if (/[[\]*]/.test(body)) {
    throw new Error(
      `JSON selector path "${path}" uses array/wildcard syntax, which is not yet supported — use dot-notation object keys (e.g. "$.a.b").`,
    )
  }
  const segments = body.split('.')
  for (const segment of segments) {
    if (segment === '') {
      throw new Error(
        `JSON selector path "${path}" is malformed (empty segment / ".." / stray dot) — use dot-notation object keys (e.g. "$.a.b").`,
      )
    }
    if (FORBIDDEN_SEGMENTS.has(segment)) {
      throw new Error(
        `JSON selector path "${path}" addresses the forbidden key "${segment}".`,
      )
    }
  }
  return segments
}

/** `$`-rooted JSONPath for `encryptQuery`'s selector needle. */
export function jsonPathOf(segments: string[]): string {
  return `$.${segments.join('.')}`
}

/**
 * A selector compares a single scalar LEAF. Returns a reason string when `value`
 * is unsupported — a non-scalar (object/array → that's `contains`), or a boolean
 * under an ordering operator (no ordering term) — else `null`. Callers raise it
 * as their adapter's operator error with column context, so a bad value is an
 * actionable SDK error rather than a deferred, opaque DB failure.
 */
export function unsupportedLeafReason(
  value: unknown,
  ordering: boolean,
): string | null {
  const isScalar =
    value instanceof Date ||
    typeof value === 'number' ||
    typeof value === 'bigint' ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  if (!isScalar) {
    return `a selector compares a scalar leaf, but got ${Array.isArray(value) ? 'an array' : 'an object'} — use contains() for sub-object matching.`
  }
  if (ordering && typeof value === 'boolean') {
    return 'a boolean leaf has no ordering — use eq/ne (or contains()).'
  }
  return null
}

/**
 * Nest `value` under the segments: `['a','b']` → `{ a: { b: value } }`. The
 * storage-needle document whose ste_vec entry at the path supplies the
 * ciphertext-bearing comparison entry.
 */
export function reconstructSelectorDocument(
  segments: string[],
  value: unknown,
): Record<string, unknown> {
  // Null-prototype objects: a segment like `__proto__` must become an OWN key,
  // not invoke the prototype setter (which would drop it and mis-serialize the
  // needle). JSON.stringify ignores the [[Prototype]], so this serializes fine.
  const root: Record<string, unknown> = Object.create(null)
  let cursor = root
  segments.forEach((segment, index) => {
    if (index === segments.length - 1) {
      cursor[segment] = value
    } else {
      const next: Record<string, unknown> = Object.create(null)
      cursor[segment] = next
      cursor = next
    }
  })
  return root
}
