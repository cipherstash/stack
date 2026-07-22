import * as p from '@clack/prompts'
import pg from 'pg'
import type { ColumnDef, DataType, SchemaDef, V3Domain } from '../types.js'

export interface DbColumn {
  columnName: string
  dataType: string
  udtName: string
  isEqlEncrypted: boolean
}

export interface DbTable {
  tableName: string
  columns: DbColumn[]
}

/**
 * Map a Postgres `udt_name` (e.g. `int4`, `timestamptz`) onto the CipherStash
 * `DataType` taxonomy. Anything we can't classify falls back to `string`,
 * which is the safest "treat the value as opaque text" default.
 */
export function pgTypeToDataType(udtName: string): DataType {
  switch (udtName) {
    case 'int2':
    case 'int4':
    case 'int8':
    case 'float4':
    case 'float8':
    case 'numeric':
      return 'number'
    case 'bool':
      return 'boolean'
    case 'date':
    case 'timestamp':
    case 'timestamptz':
      return 'date'
    case 'json':
    case 'jsonb':
      return 'json'
    default:
      return 'string'
  }
}

/**
 * Read every base table in the `public` schema along with its columns.
 *
 * The `eql_v2_encrypted` UDT marker tells us a column is already managed by
 * CipherStash — useful for re-runs against a partially set up DB so we can
 * pre-select those columns rather than asking the user to reconfirm.
 */
export async function introspectDatabase(
  databaseUrl: string,
): Promise<DbTable[]> {
  // pg.Client defaults `connectionTimeoutMillis` to "no timeout"; without
  // this, an unreachable / firewalled database silently hangs the spinner
  // until the user kills the process. 10 s is generous for healthy hosts
  // and short enough to surface a real failure quickly.
  const client = new pg.Client({
    connectionString: databaseUrl,
    connectionTimeoutMillis: 10_000,
  })
  try {
    await client.connect()

    const { rows } = await client.query<{
      table_name: string
      column_name: string
      data_type: string
      udt_name: string
    }>(`
      SELECT c.table_name, c.column_name, c.data_type, c.udt_name
      FROM information_schema.columns c
      JOIN information_schema.tables t
        ON t.table_name = c.table_name AND t.table_schema = c.table_schema
      WHERE c.table_schema = 'public'
        AND t.table_type = 'BASE TABLE'
      ORDER BY c.table_name, c.ordinal_position
    `)

    const tableMap = new Map<string, DbColumn[]>()
    for (const row of rows) {
      const cols = tableMap.get(row.table_name) ?? []
      cols.push({
        columnName: row.column_name,
        dataType: row.data_type,
        udtName: row.udt_name,
        isEqlEncrypted: row.udt_name === 'eql_v2_encrypted',
      })
      tableMap.set(row.table_name, cols)
    }

    return Array.from(tableMap.entries()).map(([tableName, columns]) => ({
      tableName,
      columns,
    }))
  } finally {
    await client.end()
  }
}

/**
 * The v3 domains offerable for a scaffolded column of the given `DataType`,
 * ordered narrowest→widest so the interactive picker reads as an escalating
 * ladder. Each domain's query capability is fixed by its type — there is no
 * capability tuple. `boolean` and `json` have exactly one domain (storage
 * only); numeric and date types collapse to the `Integer*` / `Date*` families
 * because `pgTypeToDataType` carries no width/precision signal.
 */
export function candidateDomains(
  dataType: DataType,
): Array<{ value: V3Domain; label: string; hint: string }> {
  switch (dataType) {
    case 'string':
      return [
        {
          value: 'Text',
          label: 'Text',
          hint: 'storage only — encrypt/decrypt, no queries',
        },
        { value: 'TextEq', label: 'TextEq', hint: 'equality (=, IN)' },
        {
          value: 'TextOrd',
          label: 'TextOrd',
          hint: 'equality + order/range (<, >, BETWEEN, sort)',
        },
        {
          value: 'TextMatch',
          label: 'TextMatch',
          hint: 'free-text match only',
        },
        {
          value: 'TextSearch',
          label: 'TextSearch',
          hint: 'equality + order/range + free-text',
        },
      ]
    case 'number':
      return [
        { value: 'Integer', label: 'Integer', hint: 'storage only' },
        { value: 'IntegerEq', label: 'IntegerEq', hint: 'equality (=, IN)' },
        {
          value: 'IntegerOrd',
          label: 'IntegerOrd',
          hint: 'equality + order/range',
        },
      ]
    case 'date':
      return [
        { value: 'Date', label: 'Date', hint: 'storage only' },
        { value: 'DateEq', label: 'DateEq', hint: 'equality (=, IN)' },
        { value: 'DateOrd', label: 'DateOrd', hint: 'equality + order/range' },
      ]
    case 'boolean':
      return [{ value: 'Boolean', label: 'Boolean', hint: 'storage only' }]
    case 'json':
      return [
        {
          value: 'Json',
          label: 'Json',
          hint: 'encrypted-JSONB containment + selectors',
        },
      ]
  }
}

/**
 * The default domain pre-selected in the picker: the widest searchable domain
 * for the type. Mirrors the pre-v3 scaffold, which enabled every capability on
 * every selected column by default. Derived from `candidateDomains` (whose
 * lists are ordered narrowest→widest) so the "widest is the default" invariant
 * has a single source of truth — reordering a candidate list moves the default
 * with it, and the two can never silently drift.
 */
export function defaultDomain(dataType: DataType): V3Domain {
  const options = candidateDomains(dataType)
  return options[options.length - 1].value
}

/**
 * Interactive multi-select: which columns in which table should be encrypted?
 *
 * Returns `undefined` if the user cancels at any prompt — callers should
 * propagate the cancellation rather than treating it as "no columns selected".
 *
 * Pre-selects columns that are already `eql_v2_encrypted` so re-running on a
 * partially encrypted DB is a no-op by default.
 */
export async function selectTableColumns(
  tables: DbTable[],
): Promise<SchemaDef | undefined> {
  const selectedTable = await p.select({
    message: 'Which table do you want to encrypt columns in?',
    options: tables.map((t) => {
      const eqlCount = t.columns.filter((c) => c.isEqlEncrypted).length
      const hint =
        eqlCount > 0
          ? `${t.columns.length} columns, ${eqlCount} already encrypted`
          : `${t.columns.length} column${t.columns.length !== 1 ? 's' : ''}`
      return { value: t.tableName, label: t.tableName, hint }
    }),
  })

  if (p.isCancel(selectedTable)) return undefined

  const table = tables.find((t) => t.tableName === selectedTable)
  if (!table) return undefined

  const eqlColumns = table.columns.filter((c) => c.isEqlEncrypted)

  if (eqlColumns.length > 0) {
    p.log.info(
      `Detected ${eqlColumns.length} column${eqlColumns.length !== 1 ? 's' : ''} with eql_v2_encrypted type — pre-selected for you.`,
    )
  }

  const selectedColumns = await p.multiselect({
    message: `Which columns in "${selectedTable}" should be in the encryption schema?`,
    options: table.columns.map((col) => ({
      value: col.columnName,
      label: col.columnName,
      hint: col.isEqlEncrypted ? 'eql_v2_encrypted' : col.dataType,
    })),
    required: true,
    initialValues: eqlColumns.map((c) => c.columnName),
  })

  if (p.isCancel(selectedColumns)) return undefined

  const columns: ColumnDef[] = []
  for (const colName of selectedColumns) {
    const dbCol = table.columns.find((c) => c.columnName === colName)
    if (!dbCol) {
      // Unreachable — multiselect only emits values from the source array.
      throw new Error(`Column ${colName} not found in table ${selectedTable}`)
    }
    const dataType = pgTypeToDataType(dbCol.udtName)
    const options = candidateDomains(dataType)

    // Single-domain types (boolean, json) have nothing to choose — assign the
    // only domain without interrupting the user with a one-option prompt.
    if (options.length === 1) {
      columns.push({ name: colName, domain: options[0].value })
      continue
    }

    const domain = await p.select<V3Domain>({
      message: `Encryption domain for "${colName}" (${dataType})?`,
      options,
      initialValue: defaultDomain(dataType),
    })

    if (p.isCancel(domain)) return undefined

    columns.push({ name: colName, domain })
  }

  p.log.success(
    `Schema defined: ${selectedTable} with ${columns.length} encrypted column${columns.length !== 1 ? 's' : ''}`,
  )

  return { tableName: selectedTable, columns }
}

/**
 * Connect, introspect, and let the user pick columns in one or more tables.
 *
 * Returns `undefined` for any of:
 * - connection failure
 * - empty database (no public tables)
 * - user cancellation at any prompt
 *
 * Callers distinguish "user wanted no schemas" from "DB has nothing to pick"
 * by also checking `introspectDatabase` separately when needed.
 */
export async function buildSchemasFromDatabase(
  databaseUrl: string,
): Promise<SchemaDef[] | undefined> {
  const s = p.spinner()
  s.start('Connecting to database and reading schema...')

  let tables: DbTable[]
  try {
    tables = await introspectDatabase(databaseUrl)
  } catch (error) {
    s.stop('Failed to connect to database.')
    p.log.error(error instanceof Error ? error.message : 'Unknown error')
    return undefined
  }

  if (tables.length === 0) {
    s.stop('No tables found in the public schema.')
    return undefined
  }

  s.stop(
    `Found ${tables.length} table${tables.length !== 1 ? 's' : ''} in the public schema.`,
  )

  const schemas: SchemaDef[] = []
  // Track names already configured this run so we never offer the same
  // table twice — picking it again would push a duplicate `SchemaDef` and
  // emit duplicate encrypted-column declarations downstream.
  const alreadySelected = new Set<string>()

  while (true) {
    const remaining = tables.filter((t) => !alreadySelected.has(t.tableName))
    if (remaining.length === 0) break

    const schema = await selectTableColumns(remaining)
    if (!schema) return undefined

    alreadySelected.add(schema.tableName)
    schemas.push(schema)

    // No tables left after this one — skip the redundant "another?" prompt.
    if (alreadySelected.size === tables.length) break

    const addMore = await p.confirm({
      message: 'Encrypt columns in another table?',
      initialValue: false,
    })

    if (p.isCancel(addMore)) return undefined
    if (!addMore) break
  }

  return schemas
}
