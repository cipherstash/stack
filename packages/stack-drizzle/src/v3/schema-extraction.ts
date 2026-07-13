import {
  type AnyEncryptedV3Column,
  type AnyV3Table,
  encryptedTable,
} from '@cipherstash/stack/eql/v3'
import type { PgTable } from 'drizzle-orm/pg-core'
import { getEqlV3Column } from './column.js'

/** Drizzle stashes the SQL table name on this well-known symbol key. */
const DRIZZLE_NAME = Symbol.for('drizzle:Name')

/**
 * Read the SQL table name Drizzle stashes on a `pgTable`. Returns `undefined`
 * for a non-object or a table not built with `pgTable()`. Shared by
 * {@link extractEncryptionSchemaV3} and the operator factory so the
 * symbol-key introspection lives in exactly one place.
 */
export function getDrizzleTableName(table: unknown): string | undefined {
  if (!table || typeof table !== 'object') return undefined
  const name = (table as Record<symbol, unknown>)[DRIZZLE_NAME]
  return typeof name === 'string' ? name : undefined
}

export function extractEncryptionSchemaV3(table: PgTable): AnyV3Table {
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

  return encryptedTable(tableName, columns)
}
