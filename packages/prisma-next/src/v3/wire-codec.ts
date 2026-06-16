// Ported from packages/drizzle/src/pg/v3/codec.ts.
//
// v3 columns are CREATE DOMAIN … AS jsonb (plain jsonb wire), a DISTINCT wire
// from v2's composite literal `("…")`.

export function encodeEqlV3Wire(value: unknown): string | null {
  // null/undefined bind as SQL NULL (JS null), NOT the JSON 'null' literal:
  // the v3 domains CHECK jsonb_typeof(VALUE) = 'object', so JSONB null fails.
  if (value === null || value === undefined) return null
  return JSON.stringify(value)
}

// Param widened to `string | object | null | undefined`: the pg driver returns a
// jsonb string OR an already-parsed object, NULL for SQL NULL, and `undefined`
// for an absent column. Return is `unknown` (not drizzle's phantom <TData>): the
// v3 codec immediately wraps the result in EncryptedString.fromInternal, so the
// generic would buy nothing here.
export function decodeEqlV3Wire(value: string | object | null | undefined): unknown {
  if (value === null || value === undefined) return value
  if (typeof value === 'object') return value
  return JSON.parse(value)
}
