/**
 * Codec for the value actually stored in a v3 column: the ENCRYPTED EQL v3
 * envelope ({@link Encrypted}), not plaintext. v3 columns are
 * `CREATE DOMAIN ... AS jsonb`, so the envelope serialises as plain jsonb —
 * distinct from v2's composite-literal parser.
 */

import type { Encrypted } from '@/types'

/** Thrown when a driver value cannot be read back as an EQL v3 envelope. */
export class EqlV3CodecError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EqlV3CodecError'
  }
}

/**
 * A stored EQL envelope always carries a schema version (`v`) and a ciphertext:
 * at `c` on scalar payloads, or at `sv[0].c` on a SteVec document (`k: "sv"`),
 * which has no top-level `c`. Checking `v` plus either carrier distinguishes an
 * envelope from a bare scalar, an array, or an unrelated object — without
 * paying a full structural validation on every decrypted row.
 */
function assertEnvelope(value: unknown, source: string): Encrypted {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new EqlV3CodecError(
      `Expected an EQL encrypted envelope from ${source}, got ${Array.isArray(value) ? 'an array' : typeof value}. The column may not hold EQL data.`,
    )
  }
  const envelope = value as { v?: unknown; c?: unknown; sv?: unknown }
  const missing =
    envelope.v === undefined
      ? '"v"'
      : envelope.c === undefined && envelope.sv === undefined
        ? 'a ciphertext ("c", or "sv" for a SteVec document)'
        : undefined
  if (missing) {
    throw new EqlV3CodecError(
      `Expected an EQL encrypted envelope from ${source}, but it is missing ${missing}. The column may not hold EQL data.`,
    )
  }
  return value as Encrypted
}

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
 * undefined normalise to `null` (SQL NULL).
 *
 * Malformed and non-envelope payloads throw {@link EqlV3CodecError} rather than
 * surfacing a raw `SyntaxError` or passing a bare scalar through as though it
 * were an envelope — a wrong value here reaches `decrypt` as garbage. */
export function v3FromDriver(
  value: string | object | null | undefined,
): Encrypted | null {
  if (value === null || value === undefined) {
    return null
  }
  if (typeof value === 'object') {
    return assertEnvelope(value, 'the driver')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch (cause) {
    throw new EqlV3CodecError(
      `Failed to parse an EQL v3 encrypted envelope from the driver: ${cause instanceof Error ? cause.message : String(cause)}`,
    )
  }
  return assertEnvelope(parsed, 'the driver')
}
