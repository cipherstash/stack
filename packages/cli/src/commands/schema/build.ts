import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import * as p from '@clack/prompts'
import pg from 'pg'
import { resolveDatabaseUrl } from '../../config/database-url.js'
import { loadStashConfig } from '../../config/index.js'

type Integration = 'drizzle' | 'supabase' | 'postgresql'
type DataType = 'string' | 'number' | 'boolean' | 'date' | 'json'
type SearchOp = 'equality' | 'orderAndRange' | 'freeTextSearch'

interface ColumnDef {
  name: string
  dataType: DataType
  searchOps: SearchOp[]
}

interface SchemaDef {
  tableName: string
  columns: ColumnDef[]
}

interface DbColumn {
  columnName: string
  dataType: string
  udtName: string
  isEqlEncrypted: boolean
}

interface DbTable {
  tableName: string
  columns: DbColumn[]
}

// --- Database introspection ---

function pgTypeToDataType(udtName: string): DataType {
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

async function introspectDatabase(databaseUrl: string): Promise<DbTable[]> {
  const client = new pg.Client({ connectionString: databaseUrl })
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

// --- Code generation ---

function toCamelCase(str: string): string {
  return str.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
}

function drizzleTsType(dataType: string): string {
  switch (dataType) {
    case 'number':
      return 'number'
    case 'boolean':
      return 'boolean'
    case 'date':
      return 'Date'
    case 'json':
      return 'Record<string, unknown>'
    default:
      return 'string'
  }
}

function generateClientFromSchemas(
  integration: Integration,
  schemas: SchemaDef[],
): string {
  switch (integration) {
    case 'drizzle':
      return generateDrizzleClient(schemas)
    case 'supabase':
    case 'postgresql':
      return generateGenericClient(schemas)
  }
}

function generateDrizzleClient(schemas: SchemaDef[]): string {
  const tableDefs = schemas.map((schema) => {
    const varName = `${toCamelCase(schema.tableName)}Table`
    const schemaVarName = `${toCamelCase(schema.tableName)}Schema`

    const columnDefs = schema.columns.map((col) => {
      const opts: string[] = []
      if (col.dataType !== 'string') {
        opts.push(`dataType: '${col.dataType}'`)
      }
      if (col.searchOps.includes('equality')) {
        opts.push('equality: true')
      }
      if (col.searchOps.includes('orderAndRange')) {
        opts.push('orderAndRange: true')
      }
      if (col.searchOps.includes('freeTextSearch')) {
        opts.push('freeTextSearch: true')
      }

      const tsType = drizzleTsType(col.dataType)
      const optsStr =
        opts.length > 0 ? `, {\n    ${opts.join(',\n    ')},\n  }` : ''
      return `  ${col.name}: encryptedType<${tsType}>('${col.name}'${optsStr}),`
    })

    return `export const ${varName} = pgTable('${schema.tableName}', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
${columnDefs.join('\n')}
  createdAt: timestamp('created_at').defaultNow(),
})

const ${schemaVarName} = extractEncryptionSchema(${varName})`
  })

  const schemaVarNames = schemas.map((s) => `${toCamelCase(s.tableName)}Schema`)

  return `import { pgTable, integer, timestamp } from 'drizzle-orm/pg-core'
import { encryptedType, extractEncryptionSchema } from '@cipherstash/stack/drizzle'
import { Encryption } from '@cipherstash/stack'

${tableDefs.join('\n\n')}

export const encryptionClient = await Encryption({
  schemas: [${schemaVarNames.join(', ')}],
})
`
}

function generateGenericClient(schemas: SchemaDef[]): string {
  const tableDefs = schemas.map((schema) => {
    const varName = `${toCamelCase(schema.tableName)}Table`

    const columnDefs = schema.columns.map((col) => {
      const parts: string[] = [`  ${col.name}: encryptedColumn('${col.name}')`]

      if (col.dataType !== 'string') {
        parts.push(`.dataType('${col.dataType}')`)
      }

      for (const op of col.searchOps) {
        parts.push(`.${op}()`)
      }

      return `${parts.join('\n    ')},`
    })

    return `export const ${varName} = encryptedTable('${schema.tableName}', {
${columnDefs.join('\n')}
})`
  })

  const tableVarNames = schemas.map((s) => `${toCamelCase(s.tableName)}Table`)

  return `import { encryptedTable, encryptedColumn } from '@cipherstash/stack/schema'
import { Encryption } from '@cipherstash/stack'

${tableDefs.join('\n\n')}

export const encryptionClient = await Encryption({
  schemas: [${tableVarNames.join(', ')}],
})
`
}

// --- Shared helpers ---

function allSearchOps(dataType: DataType): SearchOp[] {
  const ops: SearchOp[] = ['equality', 'orderAndRange']
  if (dataType === 'string') {
    ops.push('freeTextSearch')
  }
  return ops
}

// --- Database-driven schema builder ---

async function selectTableColumns(
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

  const table = tables.find((t) => t.tableName === selectedTable)!
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

  const searchable = await p.confirm({
    message:
      'Enable searchable encryption on these columns? (you can fine-tune indexes later)',
    initialValue: true,
  })

  if (p.isCancel(searchable)) return undefined

  const columns: ColumnDef[] = selectedColumns.map((colName) => {
    const dbCol = table.columns.find((c) => c.columnName === colName)!
    const dataType = pgTypeToDataType(dbCol.udtName)
    const searchOps = searchable ? allSearchOps(dataType) : []
    return { name: colName, dataType, searchOps }
  })

  p.log.success(
    `Schema defined: ${selectedTable} with ${columns.length} encrypted column${columns.length !== 1 ? 's' : ''}`,
  )

  return { tableName: selectedTable, columns }
}

async function buildSchemasFromDatabase(
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

  while (true) {
    const schema = await selectTableColumns(tables)
    if (!schema) return undefined

    schemas.push(schema)

    const addMore = await p.confirm({
      message: 'Encrypt columns in another table?',
      initialValue: false,
    })

    if (p.isCancel(addMore)) return undefined
    if (!addMore) break
  }

  return schemas
}

// --- Command ---

export async function builderCommand(
  options: { supabase?: boolean; databaseUrl?: string } = {},
) {
  await resolveDatabaseUrl({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })
  const config = await loadStashConfig()

  p.intro('CipherStash Schema Builder')

  // Schema builder flow — uses DB introspection to generate a client file
  const integration: Integration = options.supabase ? 'supabase' : 'postgresql'

  const defaultPath = config.client ?? './src/encryption/index.ts'

  const clientFilePath = await p.text({
    message: 'Where should we write your encryption client?',
    placeholder: defaultPath,
    defaultValue: defaultPath,
  })

  if (p.isCancel(clientFilePath)) {
    p.cancel('Cancelled.')
    return
  }

  const resolvedPath = resolve(process.cwd(), clientFilePath)

  if (existsSync(resolvedPath)) {
    const action = await p.select({
      message: `${clientFilePath} already exists. What would you like to do?`,
      options: [
        {
          value: 'keep',
          label: 'Keep existing file',
          hint: 'cancel builder',
        },
        { value: 'overwrite', label: 'Overwrite with new schema' },
      ],
    })

    if (p.isCancel(action) || action === 'keep') {
      p.cancel('Cancelled.')
      return
    }
  }

  const schemas = await buildSchemasFromDatabase(config.databaseUrl)

  if (!schemas || schemas.length === 0) {
    p.cancel('Cancelled.')
    return
  }

  const fileContents = generateClientFromSchemas(integration, schemas)

  const dir = dirname(resolvedPath)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }

  writeFileSync(resolvedPath, fileContents, 'utf-8')
  p.log.success(`Encryption client written to ${clientFilePath}`)
  p.outro('Schema ready!')
}
