import {
  classifyEqlDomain,
  isReverseMigrationPhase,
  type MigrationStateRow,
  plaintextTypeForEqlDomain,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import {
  fetchPhysicalColumns,
  latestByColumnSafe,
} from '@/commands/encrypt/lib/db-readers.js'
import { formatTable } from '@/commands/encrypt/lib/table-format.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { createPgClient } from '@/db/client.js'
import {
  derivePlaintextName,
  isActiveReverseLifecycle,
  manifestPlaintextFor,
  recordedPlaintextColumn,
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
 * plus any column whose reverse lifecycle is on record but whose encrypted
 * column is already gone, merging:
 *
 * - `information_schema.columns` — which columns are encrypted, their domain,
 *   and whether the plaintext twin exists yet;
 * - the latest REVERSE event per encrypted column in `cs_migrations` — phase,
 *   progress, and the count of values the backfill could not decrypt.
 *
 * The twin name comes from the same rules `decrypt plan` and `decrypt
 * backfill` use (recorded pairing of the lifecycle in progress, then the
 * manifest, then {@link derivePlaintextName}), so the three commands never
 * show different names for one column. A twin that is itself an EQL column,
 * which `plan` and `backfill` refuse, is flagged `plaintext-col-is-eql`.
 *
 * Read-only, and runs no per-row coverage queries (as `encrypt status`).
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

    const rows: Row[] = []
    const seen = new Set<string>()

    for (const [table, columns] of physicalCols) {
      for (const [column, domain] of columns) {
        if (domain === null || classifyEqlDomain(domain) !== 3) continue
        const key = `${table}.${column}`
        seen.add(key)
        const latest = reverseOnly(stateMap.get(`${table}.${column}`))
        const recordedTwin = recordedPlaintextColumn(latest)
        const active = isActiveReverseLifecycle(
          latest,
          recordedTwin === undefined
            ? null
            : forwardOnly(stateMap.get(`${table}.${recordedTwin}`)),
        )
        // A finished lifecycle's events are history: this column starts over.
        const state = active ? latest : null
        const plaintext =
          (active ? recordedTwin : undefined) ??
          (await manifestPlaintextFor(table, column)) ??
          derivePlaintextName(column).name
        const twinDomain = columns.get(plaintext)
        rows.push(
          renderRow({
            table,
            column,
            domain,
            plaintext,
            state,
            plaintextExists: columns.has(plaintext),
            plaintextIsEql:
              twinDomain !== undefined &&
              twinDomain !== null &&
              classifyEqlDomain(twinDomain) !== null,
            mappedType: plaintextTypeForEqlDomain(domain)?.sqlType,
          }),
        )
      }
    }

    // Reverse lifecycles whose encrypted column is no longer visible — most
    // often `encrypted-dropped` after the migration was applied.
    for (const [key, row] of stateMap) {
      if (seen.has(key)) continue
      const state = reverseOnly(row)
      if (!state) continue
      const lastDot = key.lastIndexOf('.')
      const table = key.slice(0, lastDot)
      const column = key.slice(lastDot + 1)
      const plaintext = recordedPlaintextColumn(state) ?? '—'
      rows.push(
        renderRow({
          table,
          column,
          domain: '—',
          plaintext,
          state,
          plaintextExists: physicalCols.get(table)?.has(plaintext) ?? false,
          encryptedGone: true,
        }),
      )
    }

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

function reverseOnly(
  row: MigrationStateRow | undefined,
): MigrationStateRow | null {
  return row && isReverseMigrationPhase(row.phase) ? row : null
}

function forwardOnly(
  row: MigrationStateRow | undefined,
): MigrationStateRow | null {
  return row && !isReverseMigrationPhase(row.phase) ? row : null
}

function renderRow(input: {
  table: string
  column: string
  domain: string
  plaintext: string
  state: MigrationStateRow | null
  plaintextExists: boolean
  /** The twin's name is taken by an EQL column, so it cannot hold plaintext. */
  plaintextIsEql?: boolean
  /** The plaintext type the domain maps to — shown while the twin is absent. */
  mappedType?: string
  /** The encrypted column is no longer in the catalog. */
  encryptedGone?: boolean
}): Row {
  const { state } = input
  const flags: string[] = []
  if (input.plaintextIsEql) {
    flags.push('plaintext-col-is-eql')
  } else if (!input.plaintextExists && input.plaintext !== '—') {
    flags.push('plaintext-col-missing')
  }
  if (input.encryptedGone && state?.phase !== 'encrypted-dropped') {
    flags.push('encrypted-col-missing')
  }
  if (!input.encryptedGone && input.mappedType === undefined) {
    flags.push('unmapped-domain')
  }

  const skipped = skippedCount(state)
  const plaintext =
    input.plaintextExists || input.plaintext === '—'
      ? input.plaintext
      : `${input.plaintext} (${input.mappedType ?? '?'}, to add)`

  return {
    table: input.table,
    column: input.column,
    domain: input.domain,
    plaintext,
    phase: state?.phase ?? '—',
    progress: formatProgress(state),
    skipped: skipped === null ? '—' : skipped.toLocaleString(),
    flags: flags.join(', '),
  }
}

/** Cumulative undecryptable count recorded on the latest reverse event. */
function skippedCount(state: MigrationStateRow | null): number | null {
  const value = state?.details?.rowsSkipped
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

/**
 * Phase-aware PROGRESS framing, matching `encrypt status`:
 *
 *   decrypt-dual-writing — gate passed, no backfill yet.
 *   decrypting           — rowsProcessed/rowsTotal (an `error` event keeps
 *                          this phase, so a failed run shows where it stopped).
 *   decrypted            — complete; not a degenerate `0/0` ratio.
 *   encrypted-dropped    — drop migration generated.
 */
function formatProgress(state: MigrationStateRow | null): string {
  switch (state?.phase) {
    case 'decrypt-dual-writing':
      return '(awaiting backfill)'
    case 'decrypting': {
      if (state.rowsTotal === null) return '—'
      const processed = state.rowsProcessed ?? 0
      const pct =
        state.rowsTotal > 0
          ? Math.floor((processed / state.rowsTotal) * 100)
          : 100
      return `${processed}/${state.rowsTotal} (${pct}%)${state.event === 'error' ? ' (last run failed)' : ''}`
    }
    case 'decrypted':
      return '(backfill complete)'
    case 'encrypted-dropped':
      return '(dropped)'
    default:
      return '—'
  }
}
