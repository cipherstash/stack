import {
  type AnyEncryptedV3Column,
  type EncryptedTable,
  encryptedTable,
} from '@cipherstash/stack/eql/v3'
import type { PgTable } from 'drizzle-orm/pg-core'
import { getEqlV3Column, type V3BuilderOf } from './column.js'

/** Drizzle stashes the SQL table name on this well-known symbol key. */
const DRIZZLE_NAME = Symbol.for('drizzle:Name')

/**
 * Read the SQL table name Drizzle stashes on a `pgTable`. Returns `undefined`
 * for a non-object or a table not built with `pgTable()`. Shared by
 * {@link extractEncryptionSchema} and the operator factory so the
 * symbol-key introspection lives in exactly one place.
 */
export function getDrizzleTableName(table: unknown): string | undefined {
  if (!table || typeof table !== 'object') return undefined
  const name = (table as Record<symbol, unknown>)[DRIZZLE_NAME]
  return typeof name === 'string' ? name : undefined
}

/**
 * The v3 column map a Drizzle table carries: every branded encrypted column,
 * keyed by its JS property name and mapped to the concrete v3 builder recovered
 * from its brand; every other property (plain columns, and the `PgTable`
 * members drizzle mixes in) dropped.
 *
 * This is the type-level mirror of {@link extractEncryptionSchema}'s runtime
 * loop, and the whole reason extraction can be precisely typed: without it the
 * return collapses to the widened `AnyV3Table`, and `InferPlaintext` over an
 * extracted schema degrades to an index signature instead of a per-column
 * plaintext map (#589).
 */
export type EncryptedColumnsOf<T> = {
  [K in keyof T as [V3BuilderOf<T[K]>] extends [never]
    ? never
    : K]: V3BuilderOf<T[K]>
}

/**
 * Rebuild a Drizzle table's encrypted columns as an eql/v3 {@link EncryptedTable}.
 *
 * The return type mirrors what `encryptedTable()` itself returns —
 * `EncryptedTable<Cols> & Cols` — so the result is both a schema for
 * `Encryption({ schemas })` and a column accessor (`schema.email`), with each
 * column's concrete domain preserved. That is what keeps `InferPlaintext` /
 * `encryptModel` / `bulkEncryptModels` precisely typed against an extracted
 * schema.
 */
export function extractEncryptionSchema<T extends PgTable>(
  table: T,
): EncryptedTable<EncryptedColumnsOf<T>> & EncryptedColumnsOf<T> {
  const tableName = getDrizzleTableName(table)
  if (!tableName) {
    throw new Error(
      'Unable to read table name from Drizzle table. Use a table created with pgTable().',
    )
  }

  const columns: Record<string, AnyEncryptedV3Column> = {}
  for (const [property, column] of Object.entries(table)) {
    if (typeof column !== 'object' || column === null) continue
    const columnName =
      'name' in column && typeof column.name === 'string'
        ? column.name
        : property
    const builder = getEqlV3Column(columnName, column)
    if (builder) columns[property] = builder
  }

  if (Object.keys(columns).length === 0) {
    throw new Error(
      `No encrypted v3 columns found in table "${tableName}". Declare columns with the v3 drizzle \`types\` namespace.`,
    )
  }

  // The runtime loop above is untyped by construction — it reads properties off
  // a `PgTable` and recovers each builder dynamically — so the precise column
  // map only exists at the type level (`EncryptedColumnsOf<T>`). Narrow the
  // widened runtime value to it here; the two are kept in step by the
  // `.test-d.ts` assertions, which compare an extracted schema against the
  // hand-authored `encryptedTable({…})` it must be equivalent to.
  return encryptedTable(tableName, columns) as EncryptedTable<
    EncryptedColumnsOf<T>
  > &
    EncryptedColumnsOf<T>
}
