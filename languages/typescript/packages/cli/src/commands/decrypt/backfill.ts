import {
  appendEvent,
  type DecryptBackfillResult,
  formatCodes,
  installMigrationsSchema,
  PlaintextWriteError,
  qualifyTable,
  quoteIdent,
  runDecryptBackfill,
  UndecryptableBatchError,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'
import { loadEncryptionContext } from '@/commands/encrypt/context.js'
import { detectPkColumn } from '@/commands/encrypt/lib/db-readers.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { buildPgClientConfig, explainTlsError } from '@/db/client.js'
import {
  assessExistingTwin,
  type DecryptPair,
  openForwardMigrationMessage,
  resolveDecryptPair,
  type TwinHazard,
  twinHazardMessage,
} from './lib/resolve-pair.js'

/** Default rows per chunk — and so per `bulkDecrypt` ZeroKMS request. */
export const DEFAULT_DECRYPT_CHUNK_SIZE = 500

/**
 * Options accepted by `stash decrypt backfill`. Same flags, same meaning, as
 * `stash encrypt backfill` — with the roles of the two columns swapped:
 * `--column` is the column being migrated AWAY from, which in this direction
 * is the encrypted one.
 */
export interface DecryptBackfillCommandOptions {
  /** Physical table, e.g. `users` (`schema.table` supported). */
  table: string
  /** The EQL v3 column to decrypt, e.g. `email_encrypted`. */
  column: string
  /**
   * The plaintext twin to fill. Defaults to the pairing a previous run
   * recorded, else the forward manifest's original name, else the
   * `<name>_encrypted` convention stripped. It must already exist — add it
   * with `stash decrypt plan`.
   */
  plaintextColumn?: string
  /** Override primary-key detection. */
  pkColumn?: string
  /**
   * Rows per chunk, and so per `bulkDecrypt` call — one ZeroKMS request per
   * chunk. Default {@link DEFAULT_DECRYPT_CHUNK_SIZE}; at most
   * `MAX_DECRYPT_CHUNK_SIZE` (32767), because each row binds two parameters
   * in the chunk's write. Validated by the caller with
   * `parseDecryptChunkSize` (`./lib/chunk-size.ts`), where the raw flag text
   * is still in hand; the handler trusts it.
   */
  chunkSize?: number
  /**
   * Assert the application already writes BOTH the encrypted column and its
   * plaintext twin on every insert/update. Required (or prompted) on the
   * first run, as for the forward backfill.
   */
  confirmDualWritesDeployed?: boolean
  /**
   * Re-decrypt rows whose plaintext is already set and overwrite it (drift
   * recovery, or replacing plaintext that predates the reverse lifecycle).
   * Safe only while dual-writes are live: a row the application wrote to the
   * plaintext column alone gets the older ciphertext's value back.
   */
  force?: boolean
  /**
   * Assert that a plaintext twin which already holds values before the first
   * reverse run is current, and keep those values. Without it (or `force`)
   * the first run refuses such a twin; see {@link TwinHazard}.
   */
  confirmPlaintextCurrent?: boolean
  /**
   * Keep going when the first chunk decrypts nothing (see
   * `UndecryptableBatchError`) — for leading rows that really are all
   * lock-context bound, or a re-run where only skipped rows remain.
   */
  continueOnUndecryptable?: boolean
}

/**
 * CLI handler for `stash decrypt backfill` — the reverse of
 * `stash encrypt backfill`, on the same engine (`@cipherstash/migrate`'s
 * chunked runner): keyset pagination, one transaction per chunk with its
 * checkpoint, SIGINT/SIGTERM finishing the current chunk, resume on re-run,
 * and the `plaintext IS NULL` idempotency guard.
 *
 * Each chunk is ONE `bulkDecrypt` call, so ZeroKMS sees one request per chunk.
 * Decryption is never charged.
 *
 * Values that cannot be decrypted with these credentials — typically values
 * bound to an end-user lock context, which only that user can decrypt — are
 * skipped, counted, left NULL, and reported. There is deliberately no bypass;
 * see the lock-context limitation in the `stash-cli` docs.
 *
 * On the first run, a twin that already holds values (or is the source of a
 * forward encryption that was never dropped) is refused unless the operator
 * passes `--force` (overwrite it from the ciphertext) or
 * `--confirm-plaintext-current` (keep it). The backfill only fills NULLs, so
 * trusting stale values silently would let `decrypt drop` destroy the only
 * current copy.
 */
export async function decryptBackfillCommand(
  options: DecryptBackfillCommandOptions,
) {
  p.intro(runnerCommand(detectPackageManager(), 'stash decrypt backfill'))

  const chunkSize = options.chunkSize ?? DEFAULT_DECRYPT_CHUNK_SIZE

  const stashConfig = await loadStashConfig()
  // The same client loading `encrypt backfill` does — the user's encryption
  // client file, or the Prisma Next contract — so decryption runs as exactly
  // the credentials and keyset the application resolves.
  const ctx = await loadEncryptionContext()

  const pool = new pg.Pool({
    ...buildPgClientConfig(stashConfig.databaseUrl),
    max: 2,
  })

  const controller = new AbortController()
  const onSignal = () => {
    p.log.warn('Interrupt received; finishing current chunk and exiting.')
    controller.abort()
  }

  let db: pg.PoolClient | undefined
  let exitCode = 0
  try {
    process.on('SIGINT', onSignal)
    process.on('SIGTERM', onSignal)
    try {
      db = await pool.connect()
    } catch (error) {
      const tlsExplanation = explainTlsError(error, stashConfig.databaseUrl)
      if (tlsExplanation) throw new BackfillConfigError(tlsExplanation)
      throw error
    }

    try {
      await installMigrationsSchema(db)
    } catch (error) {
      throw new BackfillConfigError(
        'Could not create the `cipherstash.cs_migrations` tracking schema, which the reverse backfill needs to checkpoint progress.\n\n' +
          `Cause: ${error instanceof Error ? error.message : String(error)}\n\n` +
          'This database user needs CREATE on the database (to create the `cipherstash` schema) and on that schema. Grant it, or have someone run `stash eql install` once, then re-run.',
      )
    }

    const pair = await resolveDecryptPair(db, {
      table: options.table,
      encryptedColumn: options.column,
      plaintextColumn: options.plaintextColumn,
    })
    const plaintextSqlType = requirePlaintextTwin(pair)
    const pkColumn =
      options.pkColumn ?? (await detectPkColumn(db, options.table))

    p.log.info(
      `${options.table}.${pair.encryptedColumn} is ${pair.domain} — reversing into ${pair.plaintextColumn} (${plaintextSqlType}). Lifecycle: backfill → switch the app to ${pair.plaintextColumn} by name → stash decrypt drop.`,
    )

    const openForward = openForwardMigrationMessage(pair)
    if (openForward !== null) throw new BackfillConfigError(openForward)

    // Before anything is recorded: once the dual-write gate writes its event,
    // later runs treat the twin's values as this lifecycle's own.
    const hazard = await assessExistingTwin(db, pair)
    if (hazard !== null) {
      if (!options.force && !options.confirmPlaintextCurrent) {
        throw new BackfillConfigError(twinHazardMessage(pair))
      }
      if (!options.force) {
        p.log.warn(
          `Proceeding under --confirm-plaintext-current: keeping the values already in ${options.table}.${pair.plaintextColumn} and decrypting only the rows where it is NULL. You are asserting those values are current.`,
        )
      }
    }

    if (options.force) {
      p.log.warn(
        `--force will re-decrypt every row of ${options.table}.${pair.encryptedColumn} and overwrite the ${pair.plaintextColumn} values that already exist. Safe only while dual-writes are live: any row your application wrote to ${pair.plaintextColumn} alone (a newer value, or one cleared on purpose) gets the older ciphertext's value back.`,
      )
      const proceed = await p.confirm({
        message: 'Continue with --force?',
        initialValue: false,
      })
      if (p.isCancel(proceed) || !proceed) {
        p.outro('Aborted.')
        return
      }
    }

    const okToProceed = await ensureReverseDualWritesDeployed(db, {
      pair,
      confirmFlag: options.confirmDualWritesDeployed === true,
      acknowledgedHazard:
        hazard === null
          ? undefined
          : {
              hazard,
              via: options.force ? 'force' : 'confirm-plaintext-current',
            },
    })
    if (!okToProceed) {
      p.outro('Aborted.')
      return
    }

    p.log.info(
      `Decrypting ${options.table}.${pair.encryptedColumn} → ${pair.plaintextColumn} (pk: ${pkColumn}, chunk: ${chunkSize} rows = one ZeroKMS request).`,
    )

    let lastLogged = 0
    const result = await runDecryptBackfill({
      db,
      decryptionClient: ctx.client,
      tableName: options.table,
      encryptedColumn: pair.encryptedColumn,
      plaintextColumn: pair.plaintextColumn,
      plaintextSqlType,
      pkColumn,
      chunkSize,
      signal: controller.signal,
      force: options.force,
      continueOnUndecryptable: options.continueOnUndecryptable,
      onProgress: (progress) => {
        if (
          progress.rowsProcessed - lastLogged >= 5000 ||
          progress.rowsProcessed === progress.rowsTotal
        ) {
          p.log.step(
            `${progress.rowsProcessed.toLocaleString()}/${progress.rowsTotal.toLocaleString()} rows${progress.rowsSkipped > 0 ? ` (${progress.rowsSkipped.toLocaleString()} undecryptable, skipped)` : ''}`,
          )
          lastLogged = progress.rowsProcessed
        }
      },
    })

    // The closing count, when the last chunk did not already print it (rows
    // inserted during the run move the total after it was counted).
    if (result.completed && lastLogged !== result.rowsProcessed) {
      p.log.step(
        `${result.rowsProcessed.toLocaleString()} rows${result.rowsSkipped > 0 ? ` (${result.rowsSkipped.toLocaleString()} skipped)` : ''}`,
      )
    }

    if (result.rowsSkipped > 0) {
      p.log.warn(skippedReport(options.table, pair, result))
    }

    if (!result.completed) {
      p.log.warn(
        `Stopped before completion. ${result.rowsProcessed.toLocaleString()} rows processed. Re-run to resume.`,
      )
      p.outro('Paused.')
      return
    }

    p.note(
      cutoverSteps(options.table, pair, result.rowsSkipped),
      'Next steps (switch reads to plaintext)',
    )
    p.outro(
      `Decrypt backfill complete. ${result.rowsDecrypted.toLocaleString()} rows decrypted${result.rowsSkipped > 0 ? `, ${result.rowsSkipped.toLocaleString()} skipped` : ''}.`,
    )
  } catch (error) {
    if (
      error instanceof BackfillConfigError ||
      error instanceof UndecryptableBatchError ||
      error instanceof PlaintextWriteError
    ) {
      // Author-controlled diagnostics carrying only names, counts and error
      // codes — never a value — so they print verbatim.
      p.log.error(error.message)
    } else {
      // Generic message only, exactly as `encrypt backfill`: upstream errors
      // are not ours to vouch for, and a decrypt path is the last place to
      // risk echoing row data.
      p.log.error(
        `Decrypt backfill failed${error instanceof Error && /^[\w. -]+$/.test(error.name) ? ` (${error.name})` : ''}. Re-run with diagnostic logging if you need details.`,
      )
    }
    exitCode = 1
  } finally {
    process.off('SIGINT', onSignal)
    process.off('SIGTERM', onSignal)
    db?.release()
    await pool.end()
  }
  if (exitCode) process.exit(exitCode)
}

/**
 * The twin must exist before anything is decrypted into it — the CLI never
 * adds columns behind the user's migration tooling. Returns its declared type.
 */
function requirePlaintextTwin(pair: DecryptPair): string {
  if (pair.plaintextSqlType !== null) return pair.plaintextSqlType
  const suggestion = pair.mapping
    ? ` (${pair.mapping.sqlType}, mapped from ${pair.domain})`
    : ''
  throw new BackfillConfigError(
    `The plaintext column ${pair.table}.${pair.plaintextColumn}${suggestion} does not exist yet. Generate and apply it first:\n  stash decrypt plan --table ${pair.table} --column ${pair.encryptedColumn}${pair.via === 'flag' ? ` --plaintext-column ${pair.plaintextColumn}` : ''}\nIf the twin has a different name, pass --plaintext-column <name>.`,
  )
}

/**
 * The reverse dual-write gate — the mirror of `encrypt backfill`'s. Rows the
 * application writes DURING the backfill must land in both columns, or they
 * end up encrypted-only and the drop coverage check later refuses. Records a
 * `decrypt_dual_writing` event on first acceptance so re-runs skip the prompt.
 *
 * Only the reverse lifecycle IN PROGRESS passes the gate: an
 * `encrypted-dropped` event from an earlier lifecycle (the column was dropped
 * and later encrypted again) asks again.
 */
async function ensureReverseDualWritesDeployed(
  db: pg.PoolClient,
  opts: {
    pair: DecryptPair
    confirmFlag: boolean
    acknowledgedHazard?: {
      hazard: TwinHazard
      via: 'force' | 'confirm-plaintext-current'
    }
  },
): Promise<boolean> {
  const { pair } = opts
  if (pair.lifecycleActive) return true

  const isInteractive =
    Boolean(process.stdin.isTTY) && process.env.CI !== 'true'
  const target = `${pair.table}.${pair.encryptedColumn}`

  if (opts.confirmFlag) {
    p.log.warn(
      `Proceeding under --confirm-dual-writes-deployed. You are asserting that every code path that writes ${target} now also writes ${pair.plaintextColumn}. If that is not true, rows written during the backfill stay encrypted-only and you will need to re-run with --force later to recover.`,
    )
  } else if (isInteractive) {
    p.log.info(
      `${target} has no reverse-migration events yet — the backfill requires your application to already write both \`${pair.encryptedColumn}\` (ciphertext) and \`${pair.plaintextColumn}\` (plaintext) on every insert/update.`,
    )
    const ok = await p.confirm({
      message: `Has the dual-write code been deployed for ${target} → ${pair.plaintextColumn}?`,
      initialValue: false,
    })
    if (p.isCancel(ok) || !ok) return false
  } else {
    p.log.error(
      `${target} has no recorded reverse \`dual-writing\` transition. Re-run with --confirm-dual-writes-deployed once your application is writing to both columns.`,
    )
    return false
  }

  await appendEvent(db, {
    tableName: pair.table,
    columnName: pair.encryptedColumn,
    event: 'decrypt_dual_writing',
    phase: 'decrypt-dual-writing',
    details: {
      plaintextColumn: pair.plaintextColumn,
      // A twin that held values before this lifecycle: what was found and
      // which flag the operator chose. `acknowledgedWith: 'force'` opens the
      // forced-pass obligation `runDecryptBackfill` enforces on every run.
      ...(opts.acknowledgedHazard
        ? {
            existingPlaintext: opts.acknowledgedHazard.hazard.kind,
            acknowledgedWith: opts.acknowledgedHazard.via,
          }
        : {}),
    },
  })
  p.log.success(`${target} marked as 'decrypt-dual-writing' in cs_migrations.`)
  return true
}

/**
 * The warning printed when rows were skipped. Two different situations, with
 * different remedies, so they are reported apart:
 *
 * - rows that did not decrypt (typically lock-context bound): only the end
 *   user's identity can decrypt them;
 * - `NULL_PLAINTEXT` rows, whose ciphertext decrypts to an empty value that a
 *   non-JSON column can only store as the same NULL that means "not
 *   decrypted yet". Lock contexts have nothing to do with them.
 *
 * `rowsSkipped` is cumulative across resumed runs, while `skippedByCode` and
 * `nullPlaintextPks` cover this run only. Only what this run's codes show is
 * attributed to a cause; skips carried over from an earlier, interrupted run
 * are reported apart, without guessing which kind they were.
 */
export function skippedReport(
  table: string,
  pair: Pick<
    DecryptPair,
    'encryptedColumn' | 'plaintextColumn' | 'plaintextSqlType'
  >,
  result: Pick<
    DecryptBackfillResult,
    'rowsSkipped' | 'skippedByCode' | 'nullPlaintextPks'
  >,
): string {
  const { NULL_PLAINTEXT: nullThisRun = 0, ...failedCodes } =
    result.skippedByCode
  const failed = Object.values(failedCodes).reduce((sum, n) => sum + n, 0)
  const carriedOver = Math.max(0, result.rowsSkipped - nullThisRun - failed)
  const paragraphs: string[] = []

  if (carriedOver > 0) {
    paragraphs.push(
      `${carriedOver.toLocaleString()} row(s) of ${table}.${pair.encryptedColumn} were skipped by an earlier run of this backfill, before this run resumed from its checkpoint, and were left with ${pair.plaintextColumn} NULL. This run did not revisit them, so it cannot say why they were skipped: the earlier run's report, or the per-code tallies in its cipherstash.cs_migrations events, name the cause. \`stash decrypt drop\` refuses while any of them still holds ciphertext.`,
    )
  }

  if (failed > 0) {
    const codes = ` This run: ${formatCodes(failedCodes)}.`
    paragraphs.push(
      `${failed.toLocaleString()} row(s) of ${table}.${pair.encryptedColumn} could not be decrypted with these credentials and were left with ${pair.plaintextColumn} NULL.${codes} The usual cause is a value bound to an end-user lock context: only that user's identity can decrypt it, and the CLI has no way to act as them. Decrypt those rows in your application on behalf of each user (writing ${pair.plaintextColumn}), then re-run this backfill. \`stash decrypt drop\` refuses while any of them remain, because dropping ${pair.encryptedColumn} would destroy their only copy.`,
    )
  }

  if (nullThisRun > 0) {
    const sample = result.nullPlaintextPks
    const more =
      nullThisRun > sample.length ? ` (first ${sample.length} shown)` : ''
    paragraphs.push(
      `${nullThisRun.toLocaleString()} row(s) of ${table}.${pair.encryptedColumn} hold ciphertext that decrypts to an empty (null) value. ${pair.plaintextColumn}${pair.plaintextSqlType ? ` (${pair.plaintextSqlType})` : ''} can only store that as NULL, which is also what "not decrypted yet" looks like, so they were left NULL. This is not a credentials or lock-context problem, and re-running will not change it. \`stash decrypt drop\` refuses while they hold ciphertext. Once you have confirmed in your application that these values really are empty, clear their ciphertext and generate the drop:\n  UPDATE ${qualifyTable(table)} SET ${quoteIdent(pair.encryptedColumn)} = NULL WHERE ${quoteIdent(pair.plaintextColumn)} IS NULL AND <primary key> IN (...);\nPrimary keys${more}: ${sample.join(', ')}`,
    )
  }

  return paragraphs.join('\n\n')
}

function cutoverSteps(
  table: string,
  pair: DecryptPair,
  rowsSkipped: number,
): string {
  const drop = `stash decrypt drop --table ${table} --column ${pair.encryptedColumn}`
  return [
    `1. Point your application's reads at ${pair.plaintextColumn} and deploy:`,
    `   - Drizzle: query ${pair.plaintextColumn} directly (no decryptModel).`,
    `   - Prisma Next: read the plain ${pair.plaintextColumn} field instead of the cipherstash.* one.`,
    `   - Other: select ${pair.plaintextColumn} instead of decrypting ${pair.encryptedColumn}.`,
    `   Keep writing BOTH ${pair.encryptedColumn} and ${pair.plaintextColumn} on every insert and update until the drop migration is applied. If writes to ${pair.encryptedColumn} stop early, a value cleared in ${pair.plaintextColumn} leaves its old ciphertext behind: \`decrypt drop\` then refuses, and a re-run of this backfill (or --force) writes the old value back.`,
    rowsSkipped > 0
      ? `2. Resolve the ${rowsSkipped.toLocaleString()} undecryptable row(s) first (see the warning above), then: ${drop}`
      : `2. Generate the encrypted-column drop: ${drop}`,
  ].join('\n')
}
