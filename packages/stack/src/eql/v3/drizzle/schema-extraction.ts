import type { PgTable } from 'drizzle-orm/pg-core'
import {
  type AnyEncryptedV3Column,
  type AnyV3Table,
  encryptedTable,
} from '@/eql/v3'
import { getEqlV3Column } from './column.js'

export function extractEncryptionSchemaV3(table: PgTable): AnyV3Table {
  // biome-ignore lint/suspicious/noExplicitAny: drizzle stores table metadata on symbols
  const tableName = (table as any)[Symbol.for('drizzle:Name')] as
    | string
    | undefined
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
