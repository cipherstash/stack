/**
 * JSONB path utilities for converting between path formats.
 *
 * These utilities support dot-notation and basic JSONPath-style array indices (e.g., "[0]").
 * Only limited validation is performed (forbidden prototype keys); callers should still
 * ensure segments are valid property names.
 */

/**
 * Convert a dot-notation path to JSONPath selector format.
 *
 * @example
 * toJsonPath("user.email")     // "$.user.email"
 * toJsonPath("$.user.email")   // "$.user.email" (unchanged)
 * toJsonPath(".user.email")    // "$.user.email"
 * toJsonPath("name")           // "$.name"
 */
export function toJsonPath(path: string): string {
  if (!path || path === '$') return '$'
  if (path.startsWith('$[')) return path
  if (path.startsWith('$.')) return path
  if (path.startsWith('$')) return `$.${path.slice(1)}`
  if (path.startsWith('.')) return `$${path}`
  if (path.startsWith('[')) return `$${path}`
  return `$.${path}`
}

/**
 * Parse a JSONB path string into segments.
 * Handles both dot notation and JSONPath format.
 *
 * Returns an empty array for empty, null, or undefined input (defensive for JS consumers).
 *
 * @example
 * parseJsonbPath("user.email")      // ["user", "email"]
 * parseJsonbPath("$.user.email")    // ["user", "email"]
 * parseJsonbPath("name")            // ["name"]
 * parseJsonbPath("$.name")          // ["name"]
 */
export function parseJsonbPath(path: string): string[] {
  if (!path || typeof path !== 'string') return []

  // Remove leading $. or $ prefix
  const normalized = path.replace(/^\$\.?/, '')

  if (!normalized) return []

  return normalized.split('.').filter(Boolean)
}

/**
 * Build a nested object from a dot-notation path and value.
 *
 * @example
 * buildNestedObject("user.role", "admin")
 * // Returns: { user: { role: "admin" } }
 *
 * buildNestedObject("name", "alice")
 * // Returns: { name: "alice" }
 *
 * buildNestedObject("a.b.c", 123)
 * // Returns: { a: { b: { c: 123 } } }
 */
const FORBIDDEN_KEYS = ['__proto__', 'prototype', 'constructor']

function validateSegment(segment: string): void {
  if (FORBIDDEN_KEYS.includes(segment)) {
    throw new Error(`Path contains forbidden segment: ${segment}`)
  }
}

export function buildNestedObject(
  path: string,
  value: unknown,
): Record<string, unknown> {
  if (!path) {
    throw new Error('Path cannot be empty')
  }

  const segments = parseJsonbPath(path)
  if (segments.length === 0) {
    throw new Error('Path must contain at least one segment')
  }

  const result: Record<string, unknown> = Object.create(null)
  let current = result

  for (let i = 0; i < segments.length - 1; i++) {
    const key = segments[i]
    validateSegment(key)
    current[key] = Object.create(null)
    current = current[key] as Record<string, unknown>
  }

  const leafKey = segments[segments.length - 1]
  validateSegment(leafKey)
  current[leafKey] = value
  return result
}
