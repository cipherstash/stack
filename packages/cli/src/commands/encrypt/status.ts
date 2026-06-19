import { type MigrationPhase, readManifest } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import {
  type EqlColumnInfo,
  fetchActiveEqlConfig,
  fetchPhysicalColumns,
  latestByColumnSafe,
} from './lib/db-readers.js'

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
  p.intro(runnerCommand(detectPackageManager(), 'stash encrypt status'))

  const config = await loadStashConfig()
  const manifest = await readManifest(process.cwd())
  const client = new pg.Client({ connectionString: config.databaseUrl })
  let exitCode = 0

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
          const key: `${string}.${string}` = `${tableName}.${column.column}`
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
      // `key` is `${tableName}.${columnName}` where tableName itself may
      // be schema-qualified (`public.users`). Split on the *last* dot so
      // the schema prefix stays attached to the table.
      const lastDot = key.lastIndexOf('.')
      const tableName = key.slice(0, lastDot)
      const columnName = key.slice(lastDot + 1)
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
        'No encrypted columns yet. Run `stash db push` to register columns with EQL, then `stash encrypt backfill --table <t> --column <c>` once your application is dual-writing.',
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
    exitCode = 1
  } finally {
    await client.end()
  }
  if (exitCode) process.exit(exitCode)
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

  // The PROGRESS column means different things in different phases. The
  // raw rowsProcessed/rowsTotal numbers in cs_migrations come from the
  // backfill engine, but rendering them as a uniform fraction across
  // every phase produces nonsense at the boundaries (e.g. `0/0 (100%)`
  // for a `backfilled` column that needed no encrypting because dual-
  // writes covered every row from seeding). Frame per phase.
  const progress = formatProgress(phase, state)

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

/**
 * Phase-aware framing for the PROGRESS column.
 *
 *   schema-added  — no backfill has run, no progress data yet.
 *   dual-writing  — backfill hasn't started either; the meaningful
 *                   measurement here is "is dual-write code populating
 *                   every new row?", which requires a live coverage
 *                   query against the user's table. We don't run that
 *                   here (the row would have to do its own SELECT) so
 *                   we surface "(awaiting backfill)" — see follow-ups.
 *   backfilling   — show backfill progress: rowsProcessed/rowsTotal.
 *                   Percentage based on rows already done.
 *   backfilled    — show "(complete)" instead of a degenerate ratio.
 *                   `0/0` here means "nothing needed encrypting
 *                   because dual-writes already covered every row" —
 *                   not a failure, but unintuitive as a fraction.
 *   cut-over      — physical rename complete, encrypted column live.
 *   dropped       — plaintext column gone, lifecycle complete.
 */
function formatProgress(
  phase: MigrationPhase | '—',
  state: {
    rowsProcessed: number | null
    rowsTotal: number | null
  } | null,
): string {
  switch (phase) {
    case 'schema-added':
      return '—'
    case 'dual-writing':
      return '(awaiting backfill)'
    case 'backfilling': {
      if (!state || state.rowsTotal === null || state.rowsTotal === undefined) {
        return '—'
      }
      const pct =
        state.rowsTotal > 0
          ? Math.floor(((state.rowsProcessed ?? 0) / state.rowsTotal) * 100)
          : 100
      return `${state.rowsProcessed ?? 0}/${state.rowsTotal} (${pct}%)`
    }
    case 'backfilled':
      return '(backfill complete)'
    case 'cut-over':
      return '(cut over)'
    case 'dropped':
      return '(dropped)'
    default:
      return '—'
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
