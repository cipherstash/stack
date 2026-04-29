import { loadStashConfig } from '@/config/index.js'
import {
  type MigrationPhase,
  latestByColumn,
  readManifest,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'

interface Row {
  table: string
  column: string
  phase: string
  eql: string
  indexes: string
  progress: string
  flags: string
}

/**
 * CLI handler for `stash encrypt status`. Renders a table with one row per
 * known (table, column), merging three sources:
 *
 * - The repo manifest (`.cipherstash/migrations.json`) — declared intent.
 * - The active / pending `eql_v2_configuration` row — EQL state + indexes.
 * - The latest `cs_migrations` event per column — runtime phase + progress.
 *
 * Plus `information_schema.columns` to surface structural drift (for
 * example: intent says a column should be encrypted, but the
 * `<col>_encrypted` column doesn't exist yet).
 */
export async function statusCommand() {
  p.intro('npx @cipherstash/cli encrypt status')

  const config = await loadStashConfig()
  const manifest = await readManifest(process.cwd())
  const client = new pg.Client({ connectionString: config.databaseUrl })

  try {
    await client.connect()

    const [stateMap, eqlConfig, physicalCols] = await Promise.all([
      latestByColumnSafe(client),
      fetchActiveEqlConfig(client),
      fetchPhysicalColumns(client),
    ])

    const rows: Row[] = []
    const seen = new Set<string>()

    if (manifest) {
      for (const [tableName, columns] of Object.entries(manifest.tables)) {
        for (const column of columns) {
          const key = `${tableName}.${column.column}`
          seen.add(key)
          rows.push(
            renderRow({
              tableName,
              columnName: column.column,
              intentIndexes: column.indexes,
              state: stateMap.get(key) ?? null,
              eqlColumn: eqlConfig.get(key) ?? null,
              physicalColumns: physicalCols.get(tableName) ?? new Set(),
            }),
          )
        }
      }
    }

    for (const [key, state] of stateMap) {
      if (seen.has(key)) continue
      const [tableName, columnName] = key.split('.') as [string, string]
      rows.push(
        renderRow({
          tableName,
          columnName,
          intentIndexes: undefined,
          state,
          eqlColumn: eqlConfig.get(key) ?? null,
          physicalColumns: physicalCols.get(tableName) ?? new Set(),
        }),
      )
    }

    if (rows.length === 0) {
      p.log.info(
        'No encrypted columns yet. Run `stash db push` then `stash encrypt advance`.',
      )
      p.outro('Nothing to show.')
      return
    }

    p.note(formatTable(rows), 'Column migration status')
    p.outro('Done.')
  } catch (error) {
    p.log.error(
      error instanceof Error ? error.message : 'Failed to read status.',
    )
    process.exit(1)
  } finally {
    await client.end()
  }
}

async function latestByColumnSafe(client: pg.Client) {
  try {
    return await latestByColumn(client)
  } catch (err) {
    if (
      err instanceof Error &&
      /cs_migrations|schema "cipherstash"/i.test(err.message)
    ) {
      return new Map()
    }
    throw err
  }
}

interface EqlColumnInfo {
  indexes: string[]
  state: 'active' | 'pending' | 'encrypting'
}

async function fetchActiveEqlConfig(
  client: pg.Client,
): Promise<Map<string, EqlColumnInfo>> {
  const out = new Map<string, EqlColumnInfo>()
  try {
    const result = await client.query<{ state: string; data: unknown }>(
      `SELECT state, data FROM eql_v2_configuration
       WHERE state IN ('active', 'pending', 'encrypting')
       ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'encrypting' THEN 1 ELSE 2 END`,
    )
    for (const row of result.rows) {
      const data = row.data as {
        tables?: Record<
          string,
          Record<string, { indexes?: Record<string, unknown> }>
        >
      } | null
      if (!data?.tables) continue
      for (const [tableName, columns] of Object.entries(data.tables)) {
        for (const [columnName, column] of Object.entries(columns)) {
          const key = `${tableName}.${columnName}`
          if (out.has(key)) continue
          out.set(key, {
            indexes: Object.keys(column.indexes ?? {}),
            state: row.state as 'active' | 'pending' | 'encrypting',
          })
        }
      }
    }
  } catch (err) {
    if (err instanceof Error && /eql_v2_configuration/i.test(err.message)) {
      return out
    }
    throw err
  }
  return out
}

async function fetchPhysicalColumns(
  client: pg.Client,
): Promise<Map<string, Set<string>>> {
  const out = new Map<string, Set<string>>()
  const result = await client.query<{
    table_name: string
    column_name: string
  }>(
    `SELECT table_name, column_name FROM information_schema.columns
     WHERE table_schema = current_schema()`,
  )
  for (const row of result.rows) {
    const set = out.get(row.table_name) ?? new Set<string>()
    set.add(row.column_name)
    out.set(row.table_name, set)
  }
  return out
}

function renderRow(input: {
  tableName: string
  columnName: string
  intentIndexes: string[] | undefined
  state: {
    phase: MigrationPhase
    rowsProcessed: number | null
    rowsTotal: number | null
  } | null
  eqlColumn: EqlColumnInfo | null
  physicalColumns: Set<string>
}): Row {
  const {
    tableName,
    columnName,
    intentIndexes,
    state,
    eqlColumn,
    physicalColumns,
  } = input

  const phase = state?.phase ?? (intentIndexes ? 'schema-added' : '—')
  const eql = eqlColumn ? eqlColumn.state : '—'
  const indexes = eqlColumn
    ? eqlColumn.indexes.join(', ') || '(none)'
    : intentIndexes?.join(', ') || '—'

  let progress = '—'
  if (state && state.rowsTotal !== null && state.rowsTotal !== undefined) {
    const pct =
      state.rowsTotal > 0
        ? Math.floor(((state.rowsProcessed ?? 0) / state.rowsTotal) * 100)
        : 100
    progress = `${state.rowsProcessed ?? 0}/${state.rowsTotal} (${pct}%)`
  }

  const flags: string[] = []
  if (intentIndexes && !eqlColumn) flags.push('not-registered')
  if (intentIndexes && !physicalColumns.has(`${columnName}_encrypted`)) {
    flags.push('encrypted-col-missing')
  }
  if (phase === 'cut-over' && !physicalColumns.has(`${columnName}_plaintext`)) {
    flags.push('plaintext-col-missing')
  }

  return {
    table: tableName,
    column: columnName,
    phase,
    eql,
    indexes,
    progress,
    flags: flags.join(', '),
  }
}

function formatTable(rows: Row[]): string {
  const headers: Row = {
    table: 'TABLE',
    column: 'COLUMN',
    phase: 'PHASE',
    eql: 'EQL',
    indexes: 'INDEXES',
    progress: 'PROGRESS',
    flags: 'FLAGS',
  }
  const all = [headers, ...rows]
  const widths: Record<keyof Row, number> = {
    table: 0,
    column: 0,
    phase: 0,
    eql: 0,
    indexes: 0,
    progress: 0,
    flags: 0,
  }
  for (const row of all) {
    for (const key of Object.keys(widths) as (keyof Row)[]) {
      widths[key] = Math.max(widths[key], row[key].length)
    }
  }
  return all
    .map((row) =>
      (Object.keys(widths) as (keyof Row)[])
        .map((k) => row[k].padEnd(widths[k]))
        .join('  '),
    )
    .join('\n')
}
