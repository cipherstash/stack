import {
  ColumnMigration,
  ColumnMigrationError,
  columnExists,
  columnSqlType,
  detectColumnEqlVersion,
  listEncryptedColumns,
  type PlaintextTypeMapping,
  plaintextTypeForEqlDomain,
  type TwinSource,
} from '@cipherstash/migrate'
import type pg from 'pg'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'

/**
 * How the plaintext twin's name was decided. Destructive steps trust only the
 * first two: `flag` is the user saying so, `recorded` is the pairing the
 * reverse backfill actually ran against. The rest are proposals.
 */
export type PlaintextResolution = TwinSource

/** One encrypted column and the plaintext twin it reverses into. */
export interface DecryptPair {
  table: string
  /** The EQL v3 column being reversed — the source. */
  encryptedColumn: string
  /** Its unqualified domain, e.g. `eql_v3_text_search`. */
  domain: string
  /**
   * The plaintext type the domain maps back to, or `null` for a domain this
   * release cannot map (a SteVec fragment, or a domain newer than the CLI).
   */
  mapping: PlaintextTypeMapping | null
  /** The plaintext twin — the target. */
  plaintextColumn: string
  via: PlaintextResolution
  /**
   * The twin's declared type (`format_type`) when it already exists, else
   * `null`. Present means `stash decrypt plan` has nothing left to add.
   */
  plaintextSqlType: string | null
  /**
   * The reverse column migration of this encrypted column, from
   * `@cipherstash/migrate`: its phase, the obligations it owes, and the
   * forward column migration that blocks it, if any. Every rule about the
   * pair is asked of it, not re-derived here.
   */
  migration: ColumnMigration
}

/**
 * Thrown when the twin's name belongs to an EQL column, which cannot hold
 * plaintext. A {@link BackfillConfigError}, so commands print it verbatim;
 * `decrypt status` tells it apart to flag the row instead.
 */
export class PlaintextColumnIsEqlError extends BackfillConfigError {}

/**
 * Resolve an encrypted column and the plaintext twin it reverses into.
 *
 * The SOURCE must be an EQL v3 column — named explicitly, never guessed —
 * because the reverse column migration starts from what exists. The TARGET
 * is decided by `ColumnMigration.load` in `@cipherstash/migrate`:
 * `--plaintext-column` when given (refused when it contradicts the pairing
 * the column migration in progress recorded), else that recorded pairing,
 * else the forward manifest's original name, else the `<name>_encrypted`
 * convention stripped, else `<encrypted>_plaintext`.
 *
 * Throws {@link BackfillConfigError} (printed verbatim by the commands) for a
 * source that is missing or not EQL v3, for a contradicting flag, and for a
 * target that is itself an EQL column ({@link PlaintextColumnIsEqlError}).
 */
export async function resolveDecryptPair(
  client: pg.ClientBase,
  opts: {
    table: string
    encryptedColumn: string
    plaintextColumn?: string
  },
): Promise<DecryptPair> {
  const { table, encryptedColumn } = opts

  const candidates = await listEncryptedColumns(client, table)
  const source = candidates.find((c) => c.column === encryptedColumn)
  if (!source) {
    const others =
      candidates.length > 0
        ? ` EQL v3 columns on ${table}: ${candidates.map((c) => c.column).join(', ')}.`
        : ''
    if (!(await columnExists(client, table, encryptedColumn))) {
      throw new BackfillConfigError(
        `Column ${encryptedColumn} does not exist on ${table}. Pass the ENCRYPTED column with --column (the EQL v3 column you want to move back to plaintext).${others}`,
      )
    }
    throw new BackfillConfigError(
      `${table}.${encryptedColumn} is not an EQL v3 column, so there is nothing to decrypt. Pass the ENCRYPTED column with --column.${others}`,
    )
  }

  let migration: ColumnMigration
  try {
    migration = await ColumnMigration.load(client, {
      table,
      column: encryptedColumn,
      direction: 'reverse',
      twin: opts.plaintextColumn,
    })
  } catch (error) {
    if (!(error instanceof ColumnMigrationError)) throw error
    let hint: string
    if (opts.plaintextColumn === undefined) {
      hint = 'Pass --plaintext-column <name>.'
    } else if (opts.plaintextColumn === encryptedColumn) {
      hint = 'Pass a different --plaintext-column.'
    } else {
      hint = 'Drop --plaintext-column to continue with the recorded column.'
    }
    throw new BackfillConfigError(`${error.message} ${hint}`)
  }
  const plaintextColumn = migration.twin.column

  if ((await detectColumnEqlVersion(client, table, plaintextColumn)) !== null) {
    throw new PlaintextColumnIsEqlError(
      `${table}.${plaintextColumn} is itself an EQL v3 column, so it cannot hold plaintext. Pass --plaintext-column <name> to choose another target.`,
    )
  }

  return {
    table,
    encryptedColumn,
    domain: source.domain,
    mapping: plaintextTypeForEqlDomain(source.domain),
    plaintextColumn,
    via: migration.twin.via,
    plaintextSqlType: await columnSqlType(client, table, plaintextColumn),
    migration,
  }
}

/**
 * Why no reverse column migration may start on this pair yet, or `null`: the
 * twin is the source column of a forward column migration into the encrypted
 * column that was never dropped. At most one column migration is open per
 * column pair (`ColumnMigration.blockedBy`), so the forward one must be
 * finished (`stash encrypt drop`) or abandoned first. Names and phases only,
 * never a value.
 */
export function openForwardMigrationMessage(
  pair: Pick<DecryptPair, 'table' | 'encryptedColumn' | 'plaintextColumn'> & {
    migration: Pick<ColumnMigration, 'blockedBy'>
  },
): string | null {
  const forward = pair.migration.blockedBy
  if (forward === null) return null
  return `${pair.table}.${pair.plaintextColumn} is the source of a forward encryption into ${pair.encryptedColumn} that is still open at '${forward.phase}' in cipherstash.cs_migrations. A reverse migration cannot start while it is open. Finish it with \`stash encrypt drop\` first, or, to abandon encryption instead, stop writing ${pair.encryptedColumn}, switch reads back to ${pair.plaintextColumn} and drop ${pair.encryptedColumn}: while dual-writes are live, ${pair.plaintextColumn} is still current and there is nothing to decrypt.`
}

/**
 * The two ways past a twin that already holds values, as `decrypt backfill`
 * flags: a forced pass, or a waiver.
 */
export const TWIN_HAZARD_FLAGS = {
  overwrite: '--force',
  keep: '--confirm-plaintext-current',
} as const

/**
 * The refusal (in `decrypt backfill`) or warning (in `decrypt plan`) for a
 * twin that already holds values. Names and phases only, never a value.
 */
export function twinHazardMessage(
  pair: Pick<DecryptPair, 'table' | 'encryptedColumn' | 'plaintextColumn'>,
): string {
  const twin = `${pair.table}.${pair.plaintextColumn}`
  const source = `${pair.table}.${pair.encryptedColumn}`
  return [
    `${twin} already holds values, and no reverse column migration is in progress for ${source}. Nothing records where they came from or whether they are current.`,
    `Kept as they are, stale values would survive the backfill, which fills only rows where ${pair.plaintextColumn} is NULL, and \`stash decrypt drop\` would then drop ${pair.encryptedColumn}: the only current copy.`,
    'Choose one, once the application writes BOTH columns on every insert and update:',
    `  ${TWIN_HAZARD_FLAGS.overwrite}  overwrite every row of ${pair.plaintextColumn} with the decrypted ciphertext (the safe choice when in doubt).`,
    `  ${TWIN_HAZARD_FLAGS.keep}  keep the existing values. Only when the application has written ${pair.plaintextColumn} on every insert and update for the whole time ${pair.encryptedColumn} existed.`,
  ].join('\n')
}
