/**
 * Codec for the value actually stored in a v3 column: the ENCRYPTED EQL v3
 * envelope ({@link Encrypted}), not plaintext. v3 columns are
 * `CREATE DOMAIN ... AS jsonb`, so the envelope serialises as plain jsonb —
 * distinct from v2's composite-literal parser.
 */

import type { Encrypted } from '@/types'

/**
 * `JSON.stringify` replacer that renders any stray `bigint` as its decimal
 * string instead of throwing `TypeError: Do not know how to serialize a
 * BigInt`. A well-formed EQL v3 envelope never carries a `bigint` — `bigint`
 * plaintext is encrypted to ciphertext strings before it ever reaches this
 * codec — so this is a defensive guard against a malformed envelope, never a
 * data path.
 */
function bigintSafeReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value
}

/** Serialise an encrypted envelope to a jsonb string for the driver. Null and
 * undefined map to SQL NULL (JS `null`), never the JSON `null` literal. */
export function v3ToDriver(value: Encrypted | null | undefined): string | null {
  if (value === null || value === undefined) {
    return null
  }
  return JSON.stringify(value, bigintSafeReplacer)
}

/** Parse a driver jsonb value back into an encrypted envelope. `postgres`
 * hands back an already-parsed object for jsonb; a string is parsed. Null and
 * undefined normalise to `null` (SQL NULL). */
export function v3FromDriver(
  value: string | object | null | undefined,
): Encrypted | null {
  if (value === null || value === undefined) {
    return null
  }
  if (typeof value === 'object') {
    return value as Encrypted
  }
  return JSON.parse(value) as Encrypted
}
