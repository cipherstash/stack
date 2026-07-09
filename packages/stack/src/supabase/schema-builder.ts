import { type AnyV3Table, EncryptedTable } from '@/eql/v3'
import type { AnyEncryptedV3Column } from '@/eql/v3/columns'
import { factoryForDomain } from '@/eql/v3/domain-registry'
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
 * NOTE: this does NOT reject recognized-but-unmodelled EQL domains — call
 * {@link assertModelledDomains} first; here such a column would silently become
 * a plaintext passthrough.
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

/**
 * Throw if any introspected column uses an EQL v3 domain this SDK version does
 * not model. Such a column would otherwise become a plaintext passthrough:
 * inserts fail on the domain CHECK, but reads return raw ciphertext undecrypted
 * (`decryptModel` skips columns absent from the config) — a silent data leak.
 * A domain not in `eqlDomains` (a user's own jsonb domain) is fine — plaintext.
 */
export function assertModelledDomains(
  introspection: IntrospectionResult,
  eqlDomains: Set<string>,
): void {
  for (const table of introspection) {
    for (const col of table.columns) {
      const domain = col.domainName
      if (domain === null) continue
      if (!eqlDomains.has(domain)) continue // not an EQL domain → plaintext
      if (factoryForDomain(domain)) continue // modelled → ok
      throw new Error(
        `[supabase v3]: column "${table.tableName}.${col.columnName}" uses EQL v3 domain "public.${domain}", which this @cipherstash/stack version does not model. Upgrade the package or drop the column — it cannot be used as a plaintext passthrough (reads would return ciphertext undecrypted).`,
      )
    }
  }
}
