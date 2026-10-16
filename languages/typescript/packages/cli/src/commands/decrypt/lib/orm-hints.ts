import type { PlaintextSqlType } from '@cipherstash/migrate'

/**
 * The `drizzle-orm/pg-core` column builder for each plaintext type the reverse
 * mapping can produce. Total over {@link PlaintextSqlType} — a type added to
 * the mapping without a builder here fails to compile.
 *
 * `bigint` uses `mode: 'bigint'` because that is what the encrypted column
 * decrypted to (a JS `bigint`, the full i64 range); `mode: 'number'` would
 * silently lose precision above 2^53. `timestamptz` keeps the time zone for the
 * reason the mapping chose it: the encrypted value was an instant.
 */
const DRIZZLE_BUILDERS: Record<
  PlaintextSqlType,
  { fn: string; options?: string }
> = {
  text: { fn: 'text' },
  integer: { fn: 'integer' },
  smallint: { fn: 'smallint' },
  bigint: { fn: 'bigint', options: "{ mode: 'bigint' }" },
  numeric: { fn: 'numeric' },
  real: { fn: 'real' },
  'double precision': { fn: 'doublePrecision' },
  boolean: { fn: 'boolean' },
  date: { fn: 'date' },
  timestamptz: { fn: 'timestamp', options: '{ withTimezone: true }' },
  jsonb: { fn: 'jsonb' },
}

/**
 * The Drizzle schema line that declares a plaintext twin, e.g.
 * `email: text('email'),`. Nullable on purpose: existing rows have no
 * plaintext until `stash decrypt backfill` fills them.
 */
export function drizzleColumnLine(
  column: string,
  sqlType: PlaintextSqlType,
): string {
  const { fn, options } = DRIZZLE_BUILDERS[sqlType]
  const key = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(column)
    ? column
    : JSON.stringify(column)
  const args = [singleQuoted(column), options]
    .filter((arg): arg is string => arg !== undefined)
    .join(', ')
  return `${key}: ${fn}(${args}),`
}

/** A TypeScript single-quoted string literal for `value`. */
function singleQuoted(value: string): string {
  return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
}

/** The `drizzle-orm/pg-core` imports a set of plaintext types needs. */
export function drizzleImports(types: Iterable<PlaintextSqlType>): string[] {
  return [
    ...new Set([...types].map((type) => DRIZZLE_BUILDERS[type].fn)),
  ].sort()
}
