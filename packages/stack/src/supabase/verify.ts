import { stripDomainSchema } from '@/eql/v3/domain-registry'
import type { IntrospectionResult } from './introspect'
import type { V3Schemas } from './schema-builder'

/**
 * Verify declared v3 tables against the introspected database. For every
 * declared column, assert the column exists and its introspected `domain_name`
 * matches the declared (unqualified) `eqlType`. Any mismatch throws at
 * construction — a wrong domain is caught here instead of as a 23514 CHECK
 * violation on the first query. Declaring a subset of a table's encrypted
 * columns is allowed; undeclared columns are synthesized from their domains.
 */
export function verifyDeclaredSchemas(
  schemas: V3Schemas,
  introspection: IntrospectionResult,
): void {
  const index = new Map<string, Map<string, string | null>>()
  for (const table of introspection) {
    const cols = new Map<string, string | null>()
    for (const col of table.columns) cols.set(col.columnName, col.domainName)
    index.set(table.tableName, cols)
  }

  for (const declared of Object.values(schemas)) {
    const tableName = declared.tableName
    const cols = index.get(tableName)
    if (!cols) {
      throw new Error(
        `[supabase v3]: declared table "${tableName}" was not found in the database`,
      )
    }
    for (const builder of Object.values(declared.columnBuilders)) {
      const dbName = builder.getName()
      if (!cols.has(dbName)) {
        throw new Error(
          `[supabase v3]: declared column "${tableName}.${dbName}" was not found in the database`,
        )
      }
      const expected = stripDomainSchema(builder.getEqlType())
      const actual = cols.get(dbName)
      if (actual !== expected) {
        throw new Error(
          `[supabase v3]: column "${tableName}.${dbName}" has domain "${actual ?? '(none)'}" but the schema declares "${expected}"`,
        )
      }
    }
  }
}
