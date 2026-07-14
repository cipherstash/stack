/**
 * v3 wire format: plain JSONB.
 *
 * v3 columns are `CREATE DOMAIN public.eql_v3_* AS jsonb ...`, so a cell
 * serialises as plain JSONB text — deliberately distinct from v2's
 * `eql_v2_encrypted` composite-literal wire (`("...")`,
 * see `../execution/cell-codec-factory.ts`), which this module MUST NOT
 * import or reproduce. Encode is `JSON.stringify` of the EQL payload;
 * decode is `JSON.parse` for text wires with object passthrough for pg
 * clients that pre-parse jsonb cells.
 *
 * The original plan intended these helpers to be a thin re-export of a
 * shared, framework-neutral codec lifted to `@cipherstash/stack/eql/v3`.
 * That lift has not happened (the stack's v3 barrel exports only the
 * authoring DSL), so the implementation lives here; if/when the shared
 * primitive lands, replace the bodies below with a re-export.
 */

// `bigintSafeReplacer` is LOAD-BEARING and must not be dropped: a
// well-formed envelope never carries a bigint (bigint plaintext is
// encrypted to ciphertext strings first), but a malformed envelope with
// a stray bigint would otherwise throw
// `TypeError: Do not know how to serialize a BigInt`.
function bigintSafeReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value
}

/** Serialise an EQL payload to plain JSONB text; `null`/`undefined` → `null`. */
export function v3ToDriver(value: unknown): string | null {
  if (value === null || value === undefined) return null
  return JSON.stringify(value, bigintSafeReplacer)
}

/**
 * Parse a JSONB wire back to the EQL payload. Text wires are
 * `JSON.parse`d; objects (drivers that pre-parse jsonb) pass through;
 * `null`/`undefined` are preserved as-is.
 */
export function v3FromDriver<T>(value: string | object | null | undefined): T {
  if (value === null || value === undefined) return value as T
  if (typeof value === 'object') return value as T
  return JSON.parse(value) as T
}
