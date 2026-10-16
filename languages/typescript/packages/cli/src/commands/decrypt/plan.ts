import {
  appendEvent,
  classifyEqlDomain,
  listEncryptedColumns,
  type PlaintextSqlType,
  qualifyTable,
  quoteIdent,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { detectDrizzle, detectPrismaNext } from '@/commands/db/detect.js'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'
import { fetchPhysicalColumns } from '@/commands/encrypt/lib/db-readers.js'
import {
  buildMigrationStem,
  writeMigrationFile,
} from '@/commands/encrypt/lib/migration-file.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { createPgClient } from '@/db/client.js'
import { drizzleColumnLine, drizzleImports } from './lib/orm-hints.js'
import {
  assessExistingTwin,
  type DecryptPair,
  openForwardMigrationMessage,
  resolveDecryptPair,
  TWIN_HAZARD_FLAGS,
  type TwinHazard,
  twinHazardMessage,
} from './lib/resolve-pair.js'

/**
 * Options accepted by `stash decrypt plan`. With no `table` the command is a
 * read-only overview; with one it generates the plaintext-twin migration.
 */
export interface DecryptPlanOptions {
  /** Generate for this table. Omit for the read-only overview. */
  table?: string
  /**
   * One ENCRYPTED column on `table`. Omit to plan every EQL v3 column on it.
   */
  column?: string
  /** Name the plaintext twin (single column only). */
  plaintextColumn?: string
  /** Directory for the generated `.sql` (non-Drizzle). Default `./drizzle`. */
  migrationsDir?: string
  /** Print the SQL and the schema change; write nothing. */
  dryRun?: boolean
}

/**
 * CLI handler for `stash decrypt plan` — step one of moving encrypted columns
 * back to plaintext.
 *
 * Without `--table` it mirrors `stash encrypt plan`: a read-only list of every
 * EQL v3 column in the current schema, the plaintext twin each would reverse
 * into (type mapped back from its domain), where its reverse lifecycle stands,
 * and the next command to run.
 *
 * With `--table` it produces the change that ADDS the plaintext twins:
 *
 * - **Drizzle** — the schema lines to add, for `drizzle-kit generate` to turn
 *   into a migration. Deliberately not a `--custom` migration: a hand-written
 *   ADD COLUMN never reaches drizzle-kit's snapshot, so the next `generate`
 *   after the schema edit would emit the same ADD COLUMN again and fail at
 *   migrate time with "column already exists".
 * - **Everything else** — a reviewed `.sql` migration (`ADD COLUMN IF NOT
 *   EXISTS`), written but not applied, exactly as `stash encrypt drop`
 *   delivers its migration. Prisma Next projects also get the contract change
 *   to make.
 *
 * Twins are added NULLABLE: existing rows have no plaintext until
 * `stash decrypt backfill` fills them. Restore a NOT NULL afterwards if the
 * original column had one.
 *
 * A twin that already exists is checked the way `decrypt backfill`'s first
 * run checks it: when it is the source of a forward encryption that was never
 * dropped ({@link openForwardMigrationMessage}), or holds values
 * ({@link assessExistingTwin}), plan warns with the same text the backfill
 * refuses with. Plan writes nothing for such a twin, so it warns rather than
 * fails.
 */
export async function decryptPlanCommand(options: DecryptPlanOptions = {}) {
  p.intro(runnerCommand(detectPackageManager(), 'stash decrypt plan'))

  const config = await loadStashConfig()
  const client = createPgClient(config.databaseUrl)
  let exitCode = 0

  try {
    await client.connect()

    if (options.table === undefined) {
      await renderOverview(client)
      return
    }

    if (options.plaintextColumn !== undefined && options.column === undefined) {
      throw new BackfillConfigError(
        '--plaintext-column names ONE twin, so it needs --column <encrypted column> too.',
      )
    }

    const targets =
      options.column !== undefined
        ? [options.column]
        : (await listEncryptedColumns(client, options.table)).map(
            (c) => c.column,
          )
    if (targets.length === 0) {
      p.log.info(`${options.table} has no EQL v3 columns. Nothing to plan.`)
      p.outro('Nothing to plan.')
      return
    }

    const pairs: DecryptPair[] = []
    for (const encryptedColumn of targets) {
      pairs.push(
        await resolveDecryptPair(client, {
          table: options.table,
          encryptedColumn,
          plaintextColumn: options.plaintextColumn,
        }),
      )
    }

    const unmappable = pairs.filter((pair) => pair.mapping === null)
    if (unmappable.length > 0) {
      throw new BackfillConfigError(
        `No plaintext type is known for ${unmappable.map((pair) => `${options.table}.${pair.encryptedColumn} (${pair.domain})`).join(', ')}. Add the plaintext column by hand with the type its values should have, then run \`stash decrypt backfill\` — the backfill casts to whatever type the column declares.`,
      )
    }

    const existing = pairs.filter((pair) => pair.plaintextSqlType !== null)
    const hazards = new Map<DecryptPair, TwinHazard>()
    for (const pair of existing) {
      const openForward = openForwardMigrationMessage(pair)
      if (openForward !== null) {
        p.log.warn(
          `\`stash decrypt backfill\` will refuse ${options.table}.${pair.encryptedColumn}: ${openForward}`,
        )
        continue
      }
      const hazard = await assessExistingTwin(client, pair)
      if (hazard === null) {
        p.log.info(
          `${options.table}.${pair.plaintextColumn} already exists (${pair.plaintextSqlType}) — nothing to add for ${pair.encryptedColumn}.`,
        )
        continue
      }
      hazards.set(pair, hazard)
      p.log.warn(
        `${options.table}.${pair.plaintextColumn} already exists (${pair.plaintextSqlType}), but it cannot be trusted as the plaintext twin of ${pair.encryptedColumn} as it stands. \`stash decrypt backfill\` will refuse it until you choose:\n${twinHazardMessage(pair)}`,
      )
    }
    const toAdd = pairs.filter(
      (pair): pair is MappedPair =>
        pair.plaintextSqlType === null && pair.mapping !== null,
    )

    // A twin that does not exist cannot be the live source of a forward
    // encryption, so a forward lifecycle still open under its name lost its
    // source column outside stash (an ORM migration, say). Plan is the only
    // step that can see that: once the twin below is added, the column is
    // back and indistinguishable from a forward source that was never
    // dropped, which `decrypt backfill` refuses. So the forward lifecycle is
    // closed here, recorded as observed rather than as a drop stash generated.
    for (const pair of toAdd) {
      const openForward = openForwardMigrationMessage(pair)
      if (openForward === null || pair.forwardState === null) continue
      const what = `${options.table}.${pair.plaintextColumn} does not exist, but the forward encryption into ${pair.encryptedColumn} is still open at '${pair.forwardState.phase}' in cipherstash.cs_migrations: the column was removed outside stash.`
      if (options.dryRun) {
        p.log.info(
          `${what} Without --dry-run, plan would record that forward migration as dropped so \`stash decrypt backfill\` can start.`,
        )
        continue
      }
      await appendEvent(client, {
        tableName: options.table,
        columnName: pair.plaintextColumn,
        event: 'dropped',
        phase: 'dropped',
        details: { observedAbsent: true, recordedBy: 'stash decrypt plan' },
      })
      p.log.info(`${what} Recorded it as dropped.`)
    }

    for (const pair of toAdd) {
      p.log.step(
        `${options.table}.${pair.encryptedColumn} (${pair.domain}) → ${pair.plaintextColumn} ${pair.mapping.sqlType}${describeVia(pair)}`,
      )
    }

    if (toAdd.length === 0) {
      p.note(nextSteps(options.table, pairs, hazards), 'Next')
      p.outro('Plaintext twins already in place.')
      return
    }

    const cwd = process.cwd()
    if (detectDrizzle(cwd)) {
      const lines = toAdd.map((pair) =>
        drizzleColumnLine(pair.plaintextColumn, pair.mapping.sqlType),
      )
      const imports = drizzleImports(toAdd.map((pair) => pair.mapping.sqlType))
      p.note(
        [
          `Add to the ${options.table} table in your Drizzle schema (nullable — existing rows are empty until the backfill runs):`,
          '',
          ...lines.map((line) => `  ${line}`),
          '',
          `Import from 'drizzle-orm/pg-core': ${imports.join(', ')}`,
          '',
          `Then generate and apply the migration:\n  ${runnerCommand(detectPackageManager(), 'drizzle-kit generate')}\n  ${runnerCommand(detectPackageManager(), 'drizzle-kit migrate')}`,
          '',
          'Keep the encrypted column declared, and keep writing it, until the `stash decrypt drop` migration is applied. The application dual-writes both columns from now until then.',
        ].join('\n'),
        'Drizzle schema change',
      )
      p.note(nextSteps(options.table, pairs, hazards), 'Next')
      p.outro(
        'Plan ready. No files written (drizzle-kit generates the migration).',
      )
      return
    }

    const sql = buildAddPlaintextSql(options.table, toAdd)
    if (detectPrismaNext(cwd)) {
      p.note(
        toAdd
          .map(
            (pair) =>
              `  ${pair.plaintextColumn}: a plain (non-cipherstash) field mapping to Postgres ${pair.mapping.sqlType}, optional`,
          )
          .join('\n'),
        'Prisma Next contract change',
      )
    }

    if (options.dryRun) {
      p.note(sql, 'Migration (dry run — not written)')
      p.outro('Dry run complete.')
      return
    }

    const { filePath, nextStep } = await writeMigrationFile({
      stem: buildMigrationStem(
        'add_plaintext',
        options.table,
        ...toAdd.map((pair) => pair.plaintextColumn),
      ),
      sql,
      migrationsDir: options.migrationsDir,
    })
    p.log.success(`Migration written to ${filePath}`)
    p.note(`${nextStep}\n\n${nextSteps(options.table, pairs, hazards)}`, 'Next')
    p.outro('Plaintext-twin migration generated.')
  } catch (error) {
    p.log.error(error instanceof Error ? error.message : 'Plan failed.')
    exitCode = 1
  } finally {
    await client.end()
    if (exitCode) process.exit(exitCode)
  }
}

/** A pair whose domain maps to a known plaintext type. */
type MappedPair = DecryptPair & {
  mapping: NonNullable<DecryptPair['mapping']>
}

/**
 * `ALTER TABLE … ADD COLUMN IF NOT EXISTS` for each twin. `IF NOT EXISTS`
 * keeps a re-applied or hand-raced migration from failing; the nullable
 * column is what lets it apply to a populated table without a default.
 */
export function buildAddPlaintextSql(
  table: string,
  pairs: ReadonlyArray<{
    encryptedColumn: string
    domain: string
    plaintextColumn: string
    mapping: { sqlType: PlaintextSqlType }
  }>,
): string {
  const qualifiedTable = qualifyTable(table)
  const statements = pairs.map(
    (pair) =>
      `-- ${pair.encryptedColumn} (${pair.domain}) decrypts to ${pair.mapping.sqlType}\nALTER TABLE ${qualifiedTable} ADD COLUMN IF NOT EXISTS ${quoteIdent(pair.plaintextColumn)} ${pair.mapping.sqlType};`,
  )
  return `-- Generated by stash decrypt plan
-- Adds a NULLABLE plaintext twin for each encrypted column on ${qualifiedTable}.
-- Existing rows stay NULL until \`stash decrypt backfill\` fills them.

${statements.join('\n\n')}
`
}

function describeVia(pair: DecryptPair): string {
  switch (pair.via) {
    case 'flag':
      return ''
    case 'recorded':
      return ' (recorded by an earlier reverse run)'
    case 'manifest':
      return ' (original name, from .cipherstash/migrations.json)'
    case 'convention':
      return ' (from the <name>_encrypted convention; override with --plaintext-column)'
    case 'fallback':
      return ' (no original name known; override with --plaintext-column)'
  }
}

function nextSteps(
  table: string,
  pairs: readonly DecryptPair[],
  hazards: ReadonlyMap<DecryptPair, TwinHazard> = new Map(),
): string {
  const runner = (command: string) =>
    runnerCommand(detectPackageManager(), command)
  const pinTarget = (pair: DecryptPair) =>
    pair.via === 'flag' ? ` --plaintext-column ${pair.plaintextColumn}` : ''
  const choice = (pair: DecryptPair) =>
    hazards.has(pair)
      ? ` <${TWIN_HAZARD_FLAGS.overwrite} | ${TWIN_HAZARD_FLAGS.keep}>`
      : ''
  return [
    '1. Apply the migration, then deploy application code that writes BOTH the encrypted column and its plaintext twin on every insert/update.',
    '2. Backfill the plaintext:',
    ...pairs.map(
      (pair) =>
        `     ${runner(`stash decrypt backfill --table ${table} --column ${pair.encryptedColumn}${pinTarget(pair)}${choice(pair)}`)}`,
    ),
    '3. Switch reads to the plaintext column(s) and deploy, still writing BOTH columns, then generate the encrypted-column drop (keep dual-writing until it is applied):',
    ...pairs.map(
      (pair) =>
        `     ${runner(`stash decrypt drop --table ${table} --column ${pair.encryptedColumn}`)}`,
    ),
  ].join('\n')
}

/**
 * Read-only overview: every EQL v3 column in the current schema, its proposed
 * or recorded plaintext twin, and where its reverse lifecycle stands. Mirrors
 * `stash encrypt plan`'s `+` / `→` / `✓` lines.
 */
async function renderOverview(
  client: ReturnType<typeof createPgClient>,
): Promise<void> {
  const physical = await fetchPhysicalColumns(client)
  const lines: string[] = []
  const runner = (command: string) =>
    runnerCommand(detectPackageManager(), command)

  for (const [table, columns] of physical) {
    for (const [column, domain] of columns) {
      if (domain === null || classifyEqlDomain(domain) !== 3) continue
      const key = `${table}.${column}`
      let pair: DecryptPair
      try {
        pair = await resolveDecryptPair(client, {
          table,
          encryptedColumn: column,
        })
      } catch (error) {
        // A pairing that cannot be resolved (say, the derived twin name is
        // itself an EQL column) is exactly what the user needs to see here.
        if (!(error instanceof BackfillConfigError)) throw error
        lines.push(`  ! ${key}: ${error.message}`)
        continue
      }
      const target = `${pair.plaintextColumn} ${pair.plaintextSqlType ?? pair.mapping?.sqlType ?? '(unknown type)'}`
      // An `encrypted-dropped` from an earlier, finished lifecycle is history,
      // not where this column stands now.
      const phase = pair.lifecycleActive ? pair.state?.phase : undefined

      if (phase === 'encrypted-dropped') {
        lines.push(
          `  ✓ ${key}: encrypted-dropped (apply the generated drop migration)`,
        )
      } else if (phase === 'decrypted') {
        lines.push(
          `  → ${key} → ${pair.plaintextColumn}: decrypted → switch reads to ${pair.plaintextColumn}, then ${runner(`stash decrypt drop --table ${table} --column ${column}`)}`,
        )
      } else if (phase !== undefined) {
        lines.push(
          `  → ${key} → ${pair.plaintextColumn}: ${phase} → ${runner(`stash decrypt backfill --table ${table} --column ${column}`)}`,
        )
      } else if (
        pair.forwardState !== null &&
        pair.forwardState.phase !== 'dropped'
      ) {
        lines.push(
          `  ! ${key} → ${target}: forward encryption still open at '${pair.forwardState.phase}' — finish or abandon it first, see ${runner(`stash decrypt plan --table ${table} --column ${column}`)}`,
        )
      } else if (pair.plaintextSqlType !== null) {
        const hazard = await assessExistingTwin(client, pair)
        lines.push(
          hazard === null
            ? `  → ${key} → ${target}: twin exists → ${runner(`stash decrypt backfill --table ${table} --column ${column}`)}`
            : `  ! ${key} → ${target}: twin already holds values; the backfill needs ${TWIN_HAZARD_FLAGS.overwrite} or ${TWIN_HAZARD_FLAGS.keep} — see ${runner(`stash decrypt plan --table ${table} --column ${column}`)}`,
        )
      } else if (pair.mapping === null) {
        lines.push(
          `  ! ${key} (${pair.domain}): no known plaintext type — add the twin by hand`,
        )
      } else {
        lines.push(
          `  + ${key} (${pair.domain}) → ${target}: add the plaintext twin — ${runner(`stash decrypt plan --table ${table} --column ${column}`)}`,
        )
      }
    }
  }

  if (lines.length === 0) {
    p.log.info('No EQL v3 columns in the current schema. Nothing to reverse.')
    p.outro('Nothing to plan.')
    return
  }
  p.note(lines.join('\n'), 'Reverse plan')
  p.outro('Done.')
}
