/**
 * v3 columns are CREATE DOMAIN … AS jsonb, so they serialise as plain jsonb.
 * This is a DISTINCT codec from v2's composite-literal parser (the `encryptedType`
 * customType in index.ts), not a parameterization of it (spec §5.1, §10).
 *
 * Note: TData is a phantom type — fromDriver returns the parsed value with no
 * runtime validation, mirroring v2. Do not over-trust the generic.
 */

export function v3ToDriver<TData>(value: TData): string | null {
  // Bind null/undefined as SQL NULL (return JS null), NOT the JSON null literal
  // 'null': the v3 domains CHECK jsonb_typeof(VALUE) = 'object', so a JSONB null
  // would fail the domain. SQL NULL is accepted and round-trips via v3FromDriver.
  // Drizzle's mapToDriverValue calls this hook even for null (no null guard).
  if (value === null || value === undefined) {
    return null
  }
  return JSON.stringify(value)
}

// The param type is honestly `string | object | null | undefined`: the postgres
// driver hands back a raw jsonb string OR an already-parsed object, NULL for SQL
// NULL, and Drizzle may pass `undefined` for an absent column. Typing it as `string`
// forced `as unknown as` self-casts on every runtime branch — widening the param
// removes them.
export function v3FromDriver<TData>(
  value: string | object | null | undefined,
): TData {
  if (value === null || value === undefined) {
    return value as TData
  }
  // The postgres driver may hand back an already-parsed object for jsonb.
  if (typeof value === 'object') {
    return value as TData
  }
  return JSON.parse(value) as TData
}
