import type { AnyEncryptedV3Column, AnyV3Table } from '@/eql/v3'
import type { ColumnSchema } from '@/schema'

/**
 * Everything the extension and raw-decrypt paths need to know about one
 * registered table, derived once at factory time.
 */
export type ModelTableMeta = {
  /** The Prisma model name this table is registered under (if any). */
  modelName?: string
  table: AnyV3Table
  /** JS property name → DB column name, for every encrypted column. */
  propToDb: Record<string, string>
  /** Encrypted JS property names (the keys Prisma models use). */
  encryptedProps: ReadonlySet<string>
  /**
   * Row keys whose values must be rebuilt into `Date` — the `cast_as:
   * 'date' | 'timestamp'` columns, under BOTH the property name (extension
   * rows) and the DB column name (raw SQL rows).
   */
  dateKeys: ReadonlySet<string>
}

/** Per-column context for the where/order fragment builders. */
export type ColumnContext = {
  table: AnyV3Table
  tableName: string
  builder: AnyEncryptedV3Column
  dbName: string
  /** The built index set — the authoritative capability source for gating. */
  indexes: ColumnSchema['indexes']
}

/** Derive a {@link ModelTableMeta} for one table. */
export function buildTableMeta(
  table: AnyV3Table,
  modelName?: string,
): ModelTableMeta {
  const propToDb = table.buildColumnKeyMap()
  const { columns } = table.build()

  const dateKeys = new Set<string>()
  for (const [property, dbName] of Object.entries(propToDb)) {
    const castAs = columns[dbName]?.cast_as
    // Both 'date' and 'timestamp' columns decrypt to a JS `Date`.
    if (castAs !== 'date' && castAs !== 'timestamp') continue
    dateKeys.add(property)
    dateKeys.add(dbName)
  }

  return {
    modelName,
    table,
    propToDb,
    encryptedProps: new Set(Object.keys(propToDb)),
    dateKeys,
  }
}

/**
 * Build the two lookup maps the integration runs on:
 * - `byModel`: Prisma model name → table meta (extension interception)
 * - `byColumn`: column builder instance → column context (fragment builders)
 *
 * A table registered under two model names would make the column→table
 * resolution ambiguous, so it throws.
 */
export function buildModelMap(tables: Record<string, AnyV3Table>): {
  byModel: Map<string, ModelTableMeta>
  byColumn: Map<object, ColumnContext>
} {
  const byModel = new Map<string, ModelTableMeta>()
  const byColumn = new Map<object, ColumnContext>()
  const seenTables = new Map<AnyV3Table, string>()

  for (const [modelName, table] of Object.entries(tables)) {
    const priorModel = seenTables.get(table)
    if (priorModel !== undefined) {
      throw new Error(
        `[prisma v3]: table "${table.tableName}" is registered under more than one model ("${priorModel}" and "${modelName}") — column lookups would be ambiguous`,
      )
    }
    seenTables.set(table, modelName)

    const meta = buildTableMeta(table, modelName)
    byModel.set(modelName, meta)

    for (const builder of Object.values(table.columnBuilders)) {
      byColumn.set(builder, {
        table,
        tableName: table.tableName,
        builder: builder as AnyEncryptedV3Column,
        dbName: builder.getName(),
        indexes: builder.build().indexes,
      })
    }
  }

  return { byModel, byColumn }
}

/**
 * Rebuild `Date` values on a decrypted row, covering both property-keyed
 * (extension) and db-name-keyed (raw SQL) rows. Non-mutating; idempotent if a
 * value is already a `Date`.
 */
export function reconstructRow(
  meta: ModelTableMeta,
  row: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...row }
  for (const key of meta.dateKeys) {
    const value = out[key]
    if (value == null || value instanceof Date) continue
    if (typeof value === 'string' || typeof value === 'number') {
      out[key] = new Date(value)
    }
  }
  return out
}
