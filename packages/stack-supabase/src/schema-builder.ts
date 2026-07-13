import { type AnyV3Table, EncryptedTable } from '@cipherstash/stack/eql/v3'
import type { AnyEncryptedV3Column } from '@cipherstash/stack/adapter-kit'
import { factoryForDomain } from '@cipherstash/stack/adapter-kit'
import type { IntrospectionResult } from './introspect'

/** A record of declared v3 tables, keyed by table name. */
export type V3Schemas = Record<string, AnyV3Table>

export interface SynthesizedSchema {
  /** Every introspected table (even zero-encrypted ones), keyed by table name.
   * Values hold ONLY the encrypted columns; plaintext columns live in
   * `allColumns`. */
  tables: Map<string, AnyV3Table>
  /** Full column list per table (encrypted + plaintext), for select('*'). */
  allColumns: Map<string, string[]>
}

/**
 * Build one `EncryptedTable` per introspected table from its domain columns.
 * A column whose `domainName` is NULL or absent from the registry is treated as
 * plaintext — retained in `allColumns` but not added to the table. Synthesized
 * columns are keyed by DB name (property == DB name).
 *
 * NOTE: this does NOT reject recognized-but-unmodelled EQL domains — such a
 * column silently becomes a plaintext passthrough here, and reads would return
 * raw ciphertext. `assertTableIsModelled` (index.ts) is the ONLY thing standing
 * between a caller and that leak; it must run before any builder is handed out.
 */
export function synthesizeTables(
  introspection: IntrospectionResult,
): SynthesizedSchema {
  const tables = new Map<string, AnyV3Table>()
  const allColumns = new Map<string, string[]>()

  for (const table of introspection) {
    // Null-prototype: keys are DB column names, so `__proto__` must land as an
    // own key rather than reparenting the object (which would drop the column).
    const builders: Record<string, AnyEncryptedV3Column> = Object.create(null)
    for (const col of table.columns) {
      if (col.domainName === null) continue
      const factory = factoryForDomain(col.domainName)
      if (!factory) continue // unknown / unmodelled → guarded elsewhere
      builders[col.columnName] = factory(col.columnName)
    }
    // Raw constructor (not `encryptedTable`) — no accessor copy or reserved-key
    // guard is needed, and it avoids throwing on an arbitrary DB column name
    // that happens to collide with a reserved table member.
    tables.set(table.tableName, new EncryptedTable(table.tableName, builders))
    allColumns.set(
      table.tableName,
      table.columns.map((c) => c.columnName),
    )
  }

  return { tables, allColumns }
}

/**
 * Replace synthesized tables with a merge of declared-over-synthesized columns.
 * For each declared column, drop the synthesized entry that resolves to the
 * same DB name and add the declared builder under its JS property name (so a
 * property→DB rename survives). Undeclared columns stay synthesized.
 * `allColumns` is unchanged (DB-name based, from introspection).
 */
export function mergeDeclaredTables(
  synth: SynthesizedSchema,
  schemas: V3Schemas,
): SynthesizedSchema {
  const tables = new Map(synth.tables)

  for (const declared of Object.values(schemas)) {
    const tableName = declared.tableName
    const synthesized = tables.get(tableName)

    const merged: Record<string, AnyEncryptedV3Column> = Object.create(null)
    if (synthesized) {
      for (const [prop, builder] of Object.entries(
        synthesized.columnBuilders,
      )) {
        merged[prop] = builder as AnyEncryptedV3Column
      }
    }
    for (const [prop, builder] of Object.entries(declared.columnBuilders)) {
      const dbName = builder.getName()
      if (dbName !== prop && Object.hasOwn(merged, dbName)) {
        delete merged[dbName]
      }
      merged[prop] = builder as AnyEncryptedV3Column
    }
    tables.set(tableName, new EncryptedTable(tableName, merged))
  }

  return { tables, allColumns: synth.allColumns }
}
