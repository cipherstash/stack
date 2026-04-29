import { loadStashConfig } from '@/config/index.js'
import { type MigrationPhase, appendEvent } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'

/**
 * Map a user-declared target phase to the event name we write to
 * `cs_migrations`. `backfilling` is recorded as `backfill_started`; the
 * phase itself is set to `backfilling` regardless.
 */
const PHASE_TO_EVENT: Record<
  MigrationPhase,
  | 'schema_added'
  | 'dual_writing'
  | 'backfill_started'
  | 'backfilled'
  | 'cut_over'
  | 'dropped'
> = {
  'schema-added': 'schema_added',
  'dual-writing': 'dual_writing',
  backfilling: 'backfill_started',
  backfilled: 'backfilled',
  'cut-over': 'cut_over',
  dropped: 'dropped',
}

/**
 * Options accepted by `stash encrypt advance`. Used to *declare* that a
 * column has reached a new phase — especially useful for `dual-writing`,
 * which is an app-code property that the CLI cannot detect automatically.
 */
export interface AdvanceCommandOptions {
  /** Physical table name, e.g. `users`. Supports `schema.table`. */
  table: string
  /** Physical plaintext column, e.g. `email`. */
  column: string
  /**
   * The phase the column is transitioning *to*. Records a corresponding
   * event (see {@link PHASE_TO_EVENT}). Does not enforce an order — you
   * can move backwards if needed, e.g. to re-run a backfill.
   */
  to: MigrationPhase
  /**
   * Optional free-form note, stored in the event's `details.note`. Useful
   * for capturing why a phase transition is happening ("deploy 1.23
   * introduced dual-write") so it shows up in audit queries later.
   */
  note?: string
}

/**
 * CLI handler for `stash encrypt advance`. Appends a phase-transition event
 * to `cs_migrations`. When advancing to `dual-writing`, also prints a
 * reminder about the required persistence-layer code change.
 */
export async function advanceCommand(options: AdvanceCommandOptions) {
  p.intro('npx @cipherstash/cli encrypt advance')

  const config = await loadStashConfig()
  const client = new pg.Client({ connectionString: config.databaseUrl })

  try {
    await client.connect()
    await appendEvent(client, {
      tableName: options.table,
      columnName: options.column,
      event: PHASE_TO_EVENT[options.to],
      phase: options.to,
      details: options.note ? { note: options.note } : null,
    })

    p.log.success(
      `${options.table}.${options.column} is now recorded as '${options.to}'.`,
    )

    if (options.to === 'dual-writing') {
      p.note(
        `Update your persistence layer to write this value to both columns:\n  - ${options.column} (plaintext, existing)\n  - ${options.column}_encrypted (ciphertext, via your encryption client)\n\nThen run: stash encrypt backfill --table ${options.table} --column ${options.column}`,
        'Next',
      )
    }

    p.outro('Recorded.')
  } catch (error) {
    p.log.error(
      error instanceof Error ? error.message : 'Failed to record transition.',
    )
    process.exit(1)
  } finally {
    await client.end()
  }
}
