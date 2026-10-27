import {
  ColumnMigration,
  type ColumnMigrationState,
  classifyEqlDomain,
  isReverseMigrationPhase,
  type MigrationStateRow,
  passProgress,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'
import {
  fetchPhysicalColumns,
  latestByColumnSafe,
} from '@/commands/encrypt/lib/db-readers.js'
import { formatTable } from '@/commands/encrypt/lib/table-format.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { createPgClient } from '@/db/client.js'
import {
  type DecryptPair,
  openForwardMigrationMessage,
  PlaintextColumnIsEqlError,
  resolveDecryptPair,
} from './lib/resolve-pair.js'

interface Row {
  table: string
  column: string
  domain: string
  plaintext: string
  phase: string
  progress: string
  skipped: string
  flags: string
}

const STATUS_HEADERS: Row = {
  table: 'TABLE',
  column: 'COLUMN',
  domain: 'DOMAIN',
  plaintext: 'PLAINTEXT',
  phase: 'PHASE',
  progress: 'PROGRESS',
  skipped: 'UNDECRYPTABLE',
  flags: 'FLAGS',
}

/**
 * CLI handler for `stash decrypt status` — the reverse twin of
 * `stash encrypt status`. One row per EQL v3 column in the current schema,
 * plus any column whose reverse column migration is on record but whose
 * encrypted column is already gone.
 *
 * Each row comes from the same `resolveDecryptPair` (and so the same
 * `ColumnMigration`) that `decrypt plan`, `backfill` and `drop` use, so the
 * commands never show a different twin, phase or warning for one column. A
 * twin that is itself an EQL column, which `plan` and `backfill` refuse, is
 * flagged `plaintext-col-is-eql`; one they would refuse or warn about is
 * flagged `forward-open` or `twin-has-values`.
 *
 * Read-only. Like `encrypt status` it runs no coverage counts; the only
 * per-row probe is whether an existing twin holds any value (`EXISTS`).
 */
export async function decryptStatusCommand() {
  p.intro(runnerCommand(detectPackageManager(), 'stash decrypt status'))

  const config = await loadStashConfig()
  const client = createPgClient(config.databaseUrl)
  let exitCode = 0

  try {
    await client.connect()

    const [stateMap, physicalCols] = await Promise.all([
      latestByColumnSafe(client),
      fetchPhysicalColumns(client),
    ])

    const current = await currentRows(client, physicalCols)
    const rows = [
      ...current.rows,
      ...(await goneRows(client, stateMap, current.seen, physicalCols)),
    ]

    if (rows.length === 0) {
      p.log.info(
        'No EQL v3 columns and no reverse migrations on record. Nothing to show.',
      )
      p.outro('Nothing to show.')
      return
    }

    p.note(formatTable(STATUS_HEADERS, rows), 'Reverse migration status')
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

type PhysicalColumns = Awaited<ReturnType<typeof fetchPhysicalColumns>>

/** One row per EQL v3 column in the current schema, and the keys shown. */
async function currentRows(
  client: ReturnType<typeof createPgClient>,
  physicalCols: PhysicalColumns,
): Promise<{ rows: Row[]; seen: Set<string> }> {
  const rows: Row[] = []
  const seen = new Set<string>()
  for (const [table, columns] of physicalCols) {
    for (const [column, domain] of columns) {
      if (domain === null || classifyEqlDomain(domain) !== 3) continue
      seen.add(`${table}.${column}`)
      rows.push(await currentRow(client, table, column, domain))
    }
  }
  return { rows, seen }
}

/**
 * Reverse column migrations whose encrypted column is no longer visible —
 * most often a generated drop that was applied.
 */
async function goneRows(
  client: ReturnType<typeof createPgClient>,
  stateMap: ReadonlyMap<string, MigrationStateRow>,
  seen: ReadonlySet<string>,
  physicalCols: PhysicalColumns,
): Promise<Row[]> {
  const rows: Row[] = []
  for (const [key, latest] of stateMap) {
    if (seen.has(key)) continue
    // Reverse events are keyed by the encrypted column, so a key whose latest
    // event is forward is a plaintext column, not a reversal: skip it before
    // reading its history.
    if (!isReverseMigrationPhase(latest.phase)) continue
    const lastDot = key.lastIndexOf('.')
    const table = key.slice(0, lastDot)
    const column = key.slice(lastDot + 1)
    const migration = await ColumnMigration.load(client, {
      table,
      column,
      direction: 'reverse',
      manifest: null,
    })
    // No history, or finished: a drop applied and the pair migrated back.
    if (migration.phase === null) continue
    const plaintext = migration.recordedTwin ?? '—'
    rows.push(
      renderRow({
        table,
        column,
        domain: '—',
        plaintext,
        migration,
        plaintextExists: physicalCols.get(table)?.has(plaintext) ?? false,
        encryptedGone: true,
      }),
    )
  }
  return rows
}

/** The row for an EQL v3 column that exists, from its resolved pair. */
async function currentRow(
  client: ReturnType<typeof createPgClient>,
  table: string,
  column: string,
  domain: string,
): Promise<Row> {
  let pair: DecryptPair
  try {
    pair = await resolveDecryptPair(client, { table, encryptedColumn: column })
  } catch (error) {
    if (!(error instanceof BackfillConfigError)) throw error
    const migration = await ColumnMigration.load(client, {
      table,
      column,
      direction: 'reverse',
    })
    return renderRow({
      table,
      column,
      domain,
      plaintext: migration.twin.column,
      migration,
      plaintextExists: true,
      plaintextIsEql: error instanceof PlaintextColumnIsEqlError,
    })
  }
  return renderRow({
    table,
    column,
    domain,
    plaintext: pair.plaintextColumn,
    migration: pair.migration,
    plaintextExists: pair.plaintextSqlType !== null,
    mappedType: pair.mapping?.sqlType,
    forwardOpen: openForwardMigrationMessage(pair) !== null,
    twinHasValues: await pair.migration.existingTwinValues(),
  })
}

interface RowInput {
  table: string
  column: string
  domain: string
  plaintext: string
  migration: ColumnMigrationState
  plaintextExists: boolean
  /** The twin's name is taken by an EQL column, so it cannot hold plaintext. */
  plaintextIsEql?: boolean
  /** The plaintext type the domain maps to — shown while the twin is absent. */
  mappedType?: string
  /** The encrypted column is no longer in the catalog. */
  encryptedGone?: boolean
  /** The twin is the source of a forward encryption not yet dropped. */
  forwardOpen?: boolean
  /** The twin already holds values no reverse migration wrote. */
  twinHasValues?: boolean
}

function renderRow(input: RowInput): Row {
  const { migration } = input
  const progress = passProgress(migration)
  const skipped = progress?.rowsSkipped ?? null
  const plaintext =
    input.plaintextExists || input.plaintext === '—'
      ? input.plaintext
      : `${input.plaintext} (${input.mappedType ?? '?'}, to add)`

  return {
    table: input.table,
    column: input.column,
    domain: input.domain,
    plaintext,
    phase: migration.phase ?? '—',
    progress: formatProgress(migration),
    skipped: skipped === null ? '—' : skipped.toLocaleString(),
    flags: rowFlags(input).join(', '),
  }
}

/** The FLAGS column: what the other commands would refuse or warn about. */
function rowFlags(input: RowInput): string[] {
  const { migration } = input
  const flags: string[] = []
  if (input.plaintextIsEql) {
    flags.push('plaintext-col-is-eql')
  } else if (!input.plaintextExists && input.plaintext !== '—') {
    flags.push('plaintext-col-missing')
  }
  if (input.encryptedGone && !migration.dropGenerated) {
    flags.push('encrypted-col-missing')
  }
  if (!input.encryptedGone && !input.plaintextIsEql && !input.mappedType) {
    flags.push('unmapped-domain')
  }
  if (input.forwardOpen) flags.push('forward-open')
  if (input.twinHasValues) flags.push('twin-has-values')
  if (migration.obligations.length > 0) flags.push('forced-pass-owed')
  return flags
}

/**
 * PROGRESS framing, matching `encrypt status`: awaiting backfill once
 * dual-writes are confirmed, `rowsProcessed/rowsTotal` while a pass runs (a
 * failed run shows where it stopped), complete, then dropped.
 */
function formatProgress(migration: ColumnMigrationState): string {
  if (migration.phase === null) return '—'
  if (migration.dropGenerated) return '(dropped)'
  const progress = passProgress(migration)
  if (progress === null) return '(awaiting backfill)'
  if (progress.completed) return '(backfill complete)'
  if (progress.rowsTotal === null) return '—'
  const pct =
    progress.rowsTotal > 0
      ? Math.floor((progress.rowsProcessed / progress.rowsTotal) * 100)
      : 100
  return `${progress.rowsProcessed}/${progress.rowsTotal} (${pct}%)${progress.failed ? ' (last run failed)' : ''}`
}
