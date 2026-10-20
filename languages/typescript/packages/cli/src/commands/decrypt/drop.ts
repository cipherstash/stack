import { readUninstallSql } from '@cipherstash/eql/sql'
import {
  appendEvent,
  type ColumnIndexInfo,
  countEqlColumnsInDatabase,
  countUndecrypted,
  EQL_COLUMN_PREDICATE_SQL,
  listColumnIndexes,
  qualifyTable,
  quoteIdent,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'
import {
  buildMigrationStem,
  sqlLiteral,
  writeMigrationFile,
} from '@/commands/encrypt/lib/migration-file.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { createPgClient } from '@/db/client.js'
import {
  recordedPlaintextColumn,
  resolveDecryptPair,
} from './lib/resolve-pair.js'

/**
 * Options accepted by `stash decrypt drop`. Generates — never applies — a
 * migration that drops the encrypted column once its plaintext twin is
 * complete, mirroring `stash encrypt drop`.
 */
export interface DecryptDropOptions {
  /** Physical table, e.g. `users`. */
  table: string
  /** The EQL v3 column to drop, e.g. `email_encrypted`. */
  column: string
  /**
   * The plaintext twin. Optional: the reverse backfill records the pairing,
   * and a flag that disagrees with that record is refused.
   */
  plaintextColumn?: string
  /** Directory for the generated `.sql` (non-Drizzle). Default `./drizzle`. */
  migrationsDir?: string
  /**
   * Also uninstall EQL v3 in the same migration — only when this is the LAST
   * EQL v3 column in the whole database, re-checked at apply time.
   */
  uninstallEql?: boolean
}

/**
 * CLI handler for `stash decrypt drop` — the reverse of `stash encrypt drop`,
 * and the one irreversible step of the reverse lifecycle.
 *
 * Gates, in order, each failing closed:
 *
 * 1. The column is an EQL v3 column.
 * 2. Its reverse lifecycle is at `decrypted` — the backfill finished.
 * 3. The plaintext twin is the one that backfill RECORDED, so coverage is
 *    checked against the column that was actually filled (a flag naming a
 *    different, fully-populated column would pass the check vacuously).
 * 4. Live coverage: no row has ciphertext set and plaintext NULL. Rows the
 *    backfill skipped as undecryptable (lock contexts) fail this, by design.
 *
 * The migration then re-verifies coverage at APPLY time under the same
 * ACCESS EXCLUSIVE lock the drop takes, drops every index that depends on the
 * encrypted column EXPLICITLY (the EQL-term functional indexes) and names
 * them here, then drops the column — all inside one `DO` block, so a failed
 * check drops nothing even under a non-transactional runner. With
 * `--uninstall-eql`, the EQL v3 schemas are removed in the same block when,
 * and only when, no EQL v3 column remains anywhere in the database.
 *
 * Generating records `encrypted_dropped` (as `encrypt drop` records
 * `dropped`), which stops a second migration being generated for the same
 * column. It does NOT touch `.cipherstash/migrations.json`: the migration has
 * not run yet, and its apply-time check can still abort it. The user removes
 * the entry once it is applied; until then `stash encrypt status` reports the
 * column as `reversed` rather than as drift.
 */
export async function decryptDropCommand(options: DecryptDropOptions) {
  p.intro(runnerCommand(detectPackageManager(), 'stash decrypt drop'))

  const config = await loadStashConfig()
  const client = createPgClient(config.databaseUrl)
  let exitCode = 0

  try {
    await client.connect()

    const pair = await resolveDecryptPair(client, {
      table: options.table,
      encryptedColumn: options.column,
      plaintextColumn: options.plaintextColumn,
    })

    const requiredPhase = 'decrypted'
    if (pair.state?.phase !== requiredPhase) {
      p.log.error(
        `Cannot generate the drop migration: ${options.table}.${options.column} is in reverse phase '${pair.state?.phase ?? '—'}'. Must be '${requiredPhase}' — run \`stash decrypt backfill --table ${options.table} --column ${options.column}\` to completion, switch the application's reads to the plaintext column, then drop.`,
      )
      exitCode = 1
      return
    }

    // `resolveDecryptPair` already refused a flag that contradicts the
    // record; here the record itself is required, because it is the only
    // positive evidence of which column the backfill filled.
    const plaintextColumn = recordedPlaintextColumn(pair.state)
    if (plaintextColumn === undefined) {
      p.log.error(
        `${options.table}.${options.column} reached '${requiredPhase}' but no plaintext column is recorded for it, so this command cannot verify which column holds the data. Re-run \`stash decrypt backfill --table ${options.table} --column ${options.column} --plaintext-column <name>\` (it records the pairing; already-decrypted rows are not rewritten), then drop.`,
      )
      exitCode = 1
      return
    }
    if (pair.plaintextSqlType === null) {
      p.log.error(
        `The recorded plaintext column ${options.table}.${plaintextColumn} no longer exists. Refusing to drop ${options.column}, which may now hold the only copy of this data.`,
      )
      exitCode = 1
      return
    }

    const undecrypted = await countUndecrypted(
      client,
      options.table,
      options.column,
      plaintextColumn,
    )
    if (undecrypted > 0) {
      p.log.error(
        `Refusing to generate the drop migration: ${undecrypted} row(s) in ${options.table} have "${options.column}" set but "${plaintextColumn}" NULL — dropping "${options.column}" would permanently destroy that data. Possible causes:\n  - rows written to "${options.column}" alone since the backfill (dual-writes not deployed everywhere): re-run\n      stash decrypt backfill --table ${options.table} --column ${options.column}\n  - values the backfill could not decrypt (typically bound to an end-user lock context, or reported as NULL_PLAINTEXT): see the backfill's report. Decrypt lock-bound rows in your application as each user and write "${plaintextColumn}", then re-run the backfill.\n  - values your application CLEARED in "${plaintextColumn}" after it stopped writing "${options.column}". Do NOT re-run the backfill for these: it would write the old value back. Restore dual-writes, then set "${options.column}" to NULL on those rows.\nThen generate the drop again.`,
      )
      exitCode = 1
      return
    }
    p.log.success(
      `Verified: no rows with "${options.column}" set and "${plaintextColumn}" NULL.`,
    )

    const indexes = await listColumnIndexes(
      client,
      options.table,
      options.column,
    )
    if (indexes.length > 0) {
      p.log.info(
        `The migration also drops ${indexes.length} index(es) built on ${options.column} (EQL search terms are meaningless once the column is gone):\n${indexes.map((index) => `  - ${index.schema}.${index.name}`).join('\n')}`,
      )
    }

    let uninstallStatements: string[] = []
    if (options.uninstallEql) {
      const remaining = (await countEqlColumnsInDatabase(client)) - 1
      if (remaining > 0) {
        throw new BackfillConfigError(
          `--uninstall-eql refused: ${remaining} other EQL v3 column(s) remain in this database. Uninstalling EQL drops its schemas with CASCADE, which would delete those columns and their data. Reverse them first, or drop the flag.`,
        )
      }
      uninstallStatements = splitUninstallSql(readUninstallSql())
      p.log.info(
        `This is the last EQL v3 column in the database, so the migration also uninstalls EQL v3 — its schemas and the public.eql_v3_* column domains — re-checked at apply time. \`cipherstash.cs_migrations\` is kept as the audit trail.`,
      )
    }

    const sql = buildDecryptDropSql({
      table: options.table,
      encryptedColumn: options.column,
      plaintextColumn,
      indexes,
      uninstallStatements,
    })

    const { filePath, nextStep, drizzleScaffolded } = await writeMigrationFile({
      stem: buildMigrationStem('drop_encrypted', options.table, options.column),
      sql,
      migrationsDir: options.migrationsDir,
    })

    await appendEvent(client, {
      tableName: options.table,
      columnName: options.column,
      event: 'encrypted_dropped',
      phase: 'encrypted-dropped',
      details: {
        plaintextColumn,
        migrationFile: filePath,
        drizzleScaffolded,
        droppedIndexes: indexes.map((index) => `${index.schema}.${index.name}`),
        uninstallEql: uninstallStatements.length > 0,
      },
    })

    // The forward manifest entry stays: the CLI owns `.cipherstash/`, and
    // `stash encrypt status` shows the entry as `reversed`, its final state.

    p.log.success(`Migration written to ${filePath}`)
    p.note(
      [
        nextStep,
        '',
        `Keep writing BOTH ${options.column} and ${plaintextColumn} until it is applied. The migration re-checks coverage when it runs and drops nothing if a row has ciphertext without plaintext.`,
        '',
        `Once applied, remove ${options.column} from your schema:`,
        `  - Drizzle: delete the ${options.column} column from the table definition. If the next \`drizzle-kit generate\` emits a DROP COLUMN for it, delete that statement — this migration already drops it.`,
        `  - Prisma Next: remove the cipherstash.* field from the contract and re-emit it.`,
        `  - Remove the table/column from your encryption client schema if nothing else on it is encrypted.`,
        '  - Then stop writing the encrypted column.',
      ].join('\n'),
      'Next',
    )
    p.outro('Encrypted-column drop migration generated.')
  } catch (error) {
    p.log.error(
      error instanceof Error ? error.message : 'Drop generation failed.',
    )
    exitCode = 1
  } finally {
    await client.end()
    // In `finally` for the same reason as `encrypt drop`: the guards above
    // `return` from inside `try`, which would skip a trailing exit.
    if (exitCode) process.exit(exitCode)
  }
}

/**
 * Split `@cipherstash/eql`'s uninstall SQL into single statements so each can
 * run through `EXECUTE` inside the drop's `DO` block. Line comments are
 * removed first. The file is a short list of `DROP SCHEMA … CASCADE;`
 * statements; anything that would make naive `;` splitting unsafe (a dollar
 * quote or a string literal) is refused rather than mangled.
 */
export function splitUninstallSql(sql: string): string[] {
  const stripped = sql
    .split('\n')
    .map((line) => line.replace(/--.*$/, ''))
    .join('\n')
  if (/[$']/.test(stripped)) {
    throw new BackfillConfigError(
      'The installed @cipherstash/eql uninstall script is not in the shape this CLI can embed safely (it contains quoted text). Drop --uninstall-eql and run its uninstall SQL by hand after this migration.',
    )
  }
  return stripped
    .split(';')
    .map((statement) => statement.replace(/\s+/g, ' ').trim())
    .filter((statement) => statement.length > 0)
}

/**
 * Build the encrypted-column drop. As with `stash encrypt drop`, the CLI's
 * coverage check goes stale the moment the file is written, so the migration
 * re-checks under the lock DROP COLUMN takes anyway and aborts — dropping
 * nothing — if any row gained ciphertext without plaintext in between. Every
 * DDL statement runs via `EXECUTE` inside the one `DO` block, which keeps the
 * check and the drops atomic even under runners that do not wrap files in a
 * transaction (plain `psql -f`).
 *
 * Identifiers are quoted for SQL (`quoteIdent`) and then embedded in the
 * `EXECUTE` string literal (`sqlLiteral`), so unusual names survive both
 * layers.
 */
export function buildDecryptDropSql(opts: {
  table: string
  encryptedColumn: string
  plaintextColumn: string
  indexes: readonly ColumnIndexInfo[]
  uninstallStatements: readonly string[]
}): string {
  const lit = sqlLiteral
  const qualifiedTable = qualifyTable(opts.table)
  const quotedEncrypted = quoteIdent(opts.encryptedColumn)
  const quotedPlaintext = quoteIdent(opts.plaintextColumn)

  const dropIndexes = opts.indexes.map(
    (index) =>
      `  EXECUTE '${lit(`DROP INDEX IF EXISTS ${quoteIdent(index.schema)}.${quoteIdent(index.name)}`)}';`,
  )

  const uninstall =
    opts.uninstallStatements.length > 0
      ? `

  -- --uninstall-eql: only when no EQL v3 column remains ANYWHERE. The
  -- uninstall drops the EQL schemas with CASCADE, which would take any
  -- remaining encrypted column (and its data) with it.
  SELECT count(*) INTO remaining_eql
    FROM pg_attribute a
    JOIN pg_type t ON t.oid = a.atttypid
    JOIN pg_class c ON c.oid = a.attrelid
   WHERE ${EQL_COLUMN_PREDICATE_SQL};

  IF remaining_eql > 0 THEN
    RAISE EXCEPTION 'stash decrypt drop: refusing to uninstall EQL — % EQL v3 column(s) still exist. Nothing was dropped.', remaining_eql;
  END IF;

${opts.uninstallStatements.map((statement) => `  EXECUTE '${lit(statement)}';`).join('\n')}

  -- The column domains (public.eql_v3_*) deliberately live outside the
  -- disposable EQL schemas, so that upgrades never touch encrypted columns —
  -- which also means the uninstall script leaves them behind. No column uses
  -- them any more (checked above), so remove them too. No CASCADE: anything
  -- else still depending on one fails this migration instead of being
  -- dropped silently.
  FOR leftover IN
    SELECT format('%I.%I', n.nspname, t.typname) AS name
      FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE t.typtype = 'd'
       AND n.nspname = 'public'
       AND t.typname LIKE 'eql\\_v3\\_%'
  LOOP
    EXECUTE 'DROP DOMAIN IF EXISTS ' || leftover.name;
  END LOOP;`
      : ''

  return `-- Generated by stash decrypt drop
-- Drops the encrypted column ${qualifiedTable}.${quotedEncrypted} now that its
-- plaintext twin ${quotedPlaintext} is complete.
-- Coverage is re-verified here, at apply time: the check stash ran at
-- generation time cannot see rows written after it.

DO $stash_decrypt_drop$
DECLARE
  undecrypted bigint;${opts.uninstallStatements.length > 0 ? '\n  remaining_eql bigint;\n  leftover record;' : ''}
BEGIN
  -- The lock DROP COLUMN takes anyway, acquired up front so the
  -- count-then-drop below is atomic against concurrent writes.
  LOCK TABLE ${qualifiedTable} IN ACCESS EXCLUSIVE MODE;

  SELECT count(*) INTO undecrypted
    FROM ${qualifiedTable}
   WHERE ${quotedEncrypted} IS NOT NULL
     AND ${quotedPlaintext} IS NULL;

  IF undecrypted > 0 THEN
    RAISE EXCEPTION 'stash decrypt drop: refusing to drop %.% — % row(s) have ciphertext set but % NULL. Dropping now would permanently destroy that data. Re-run: stash decrypt backfill, then regenerate this migration.',
      '${lit(qualifiedTable)}', '${lit(opts.encryptedColumn)}', undecrypted, '${lit(opts.plaintextColumn)}';
  END IF;
${dropIndexes.length > 0 ? `\n  -- Indexes built on the encrypted column's EQL terms.\n${dropIndexes.join('\n')}\n` : ''}
  EXECUTE '${lit(`ALTER TABLE ${qualifiedTable} DROP COLUMN ${quotedEncrypted}`)}';${uninstall}
END
$stash_decrypt_drop$;
`
}
