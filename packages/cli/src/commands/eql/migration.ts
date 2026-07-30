import { spawnSync } from 'node:child_process'
import { existsSync, unlinkSync, writeFileSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { MIGRATIONS_SCHEMA_SQL } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { CliExit } from '@/cli/exit.js'
import { printNextSteps, SAFE_MIGRATION_NAME } from '@/commands/db/install.js'
import {
  describeSkipReason,
  describeStagedReconciliation,
  isPartialRewriteResult,
  type PartialRewriteResult,
  rewriteEncryptedAlterColumns,
} from '@/commands/db/rewrite-migrations.js'
import {
  detectPackageManager,
  execArgv,
  execCommand,
} from '@/commands/init/utils.js'
import { loadBundledEqlSql, supabaseGrantsFor } from '@/installer/index.js'
import { messages } from '@/messages.js'

const DEFAULT_MIGRATION_NAME = 'install-eql'
const DEFAULT_DRIZZLE_OUT = 'drizzle'

/** Find the most recently generated Drizzle migration matching the name. */
export async function findGeneratedMigration(
  outDir: string,
  migrationName: string,
): Promise<string> {
  if (!existsSync(outDir)) {
    throw new Error(
      `Drizzle output directory not found: ${outDir}\nMake sure drizzle-kit is configured correctly.`,
    )
  }
  const migrationSuffix = `_${migrationName}.sql`
  const matchingFiles = (await readdir(outDir))
    .filter((entry) => entry.endsWith(migrationSuffix))
    .sort()
  if (matchingFiles.length === 0) {
    throw new Error(
      `Could not find a migration matching "${migrationName}" in ${outDir}`,
    )
  }
  return join(outDir, matchingFiles[matchingFiles.length - 1])
}

function cleanupMigrationFile(filePath: string | undefined): void {
  if (!filePath) return
  try {
    if (existsSync(filePath)) {
      unlinkSync(filePath)
      p.log.info(`Cleaned up migration file: ${filePath}`)
    }
  } catch {
    p.log.warn(`Could not clean up migration file: ${filePath}`)
  }
}

export interface EqlMigrationOptions {
  /** Emit a Drizzle custom migration. */
  drizzle?: boolean
  /**
   * Rejected with a pointer — Prisma Next installs EQL through its own
   * migration framework, so there is nothing for this command to emit.
   */
  prisma?: boolean
  /** Append the Supabase role grants (`eql_v3` + `eql_v3_internal`). */
  supabase?: boolean
  /** Migration name (Drizzle). Defaults to `install-eql`. */
  name?: string
  /** Output directory (Drizzle). Defaults to `drizzle`. */
  out?: string
  /** Describe what would happen without writing anything. */
  dryRun?: boolean
  /**
   * Run as a step inside a larger flow (`stash init`) rather than as a
   * standalone command. Suppresses the intro/outro banners and the trailing
   * `printNextSteps()` note — init renders its own summary and agent handoff,
   * so emitting ours as well would give the user two competing "what next"
   * blocks. Purely presentational: the migration written is identical.
   */
  embedded?: boolean
}

/**
 * Assemble the EQL **v3** install SQL for a generated migration.
 *
 * One source of truth: the SQL is the CLI's bundled v3 install script
 * (`loadBundledEqlSql()`) — the same bundle `stash eql install`
 * applies directly. On `--supabase` the v3 role grants are appended
 * (`supabaseGrantsFor()` → USAGE/EXECUTE on `eql_v3` + `eql_v3_internal` for
 * `anon`/`authenticated`/`service_role`), matching `stash eql install --supabase`.
 * Apps that connect directly as `postgres` don't need the grants, but they're
 * idempotent and harmless, and required when the same tables are reached via
 * PostgREST/RLS.
 *
 * Order is load-bearing: schema creation → grants (which reference that schema)
 * → the `cs_migrations` tracking schema, appended last so one migration run
 * installs everything `stash encrypt …` needs — no out-of-band `stash eql
 * install`.
 */
export function buildEqlV3MigrationSql(opts: { supabase: boolean }): string {
  const eqlSql = loadBundledEqlSql()
  const grants = opts.supabase
    ? `\n\n-- Supabase role grants: let anon/authenticated/service_role use the\n-- eql_v3 + eql_v3_internal schemas (required when tables are reached via\n-- PostgREST/RLS; harmless otherwise).\n${supabaseGrantsFor().trim()}`
    : ''
  return `${eqlSql.trim()}${grants}\n\n-- CipherStash encryption-migration tracking schema.\n-- Tracks per-column phase + backfill progress for \`stash encrypt\`.\n${MIGRATIONS_SCHEMA_SQL.trim()}\n`
}

/**
 * `stash eql migration` — generate an EQL v3 install migration for the target
 * ORM, rather than running SQL directly against the database (that's `stash eql
 * install`). Migration-first is the preferred path: the install lands in the
 * project's migration history and ships to every environment through the ORM's
 * own migrate step.
 *
 * v3 only — there is no `--eql-version` here. prisma-next never shipped v2, and
 * the Drizzle v3 surface is the documented one.
 *
 * Validation exits throw {@link CliExit} rather than `process.exit` so the
 * telemetry `finally` in `main.ts` still runs (and the branches stay unit
 * testable).
 */
export async function eqlMigrationCommand(
  options: EqlMigrationOptions,
): Promise<void> {
  const targets = [
    options.drizzle && 'drizzle',
    options.prisma && 'prisma',
  ].filter(Boolean)
  if (targets.length === 0) {
    p.log.error(messages.eql.migrationNeedsTarget)
    throw new CliExit(1)
  }
  if (targets.length > 1) {
    p.log.error(messages.eql.migrationOneTarget)
    throw new CliExit(1)
  }

  if (options.prisma) {
    // Prisma Next does not need an emitted install migration: its extension
    // pack contributes the `migrations/cipherstash/` contract space, which
    // installs the EQL bundle through prisma-next's own migration framework.
    // The flag exists only to route people who try it to that mechanism.
    p.log.error(messages.eql.migrationPrismaNotNeeded)
    throw new CliExit(1)
  }

  await generateDrizzleEqlMigration(options)
}

async function generateDrizzleEqlMigration(
  options: EqlMigrationOptions,
): Promise<void> {
  const migrationName = options.name ?? DEFAULT_MIGRATION_NAME
  if (!SAFE_MIGRATION_NAME.test(migrationName)) {
    p.log.error(messages.eql.migrationBadName)
    throw new CliExit(1)
  }
  const outDir = resolve(options.out ?? DEFAULT_DRIZZLE_OUT)
  const pm = detectPackageManager()

  // Run the PROJECT-LOCAL drizzle-kit (`pnpm exec` / `npx --no-install`), not the
  // download-and-run form — it must resolve this project's drizzle.config.ts and
  // schema. Invoke via spawnSync with an argv array (no shell), so a `--name`
  // carrying spaces or shell metacharacters is one inert token, never word-split
  // or executed. `--out` is always passed so drizzle-kit WRITES where we then
  // LOOK — otherwise a project whose drizzle.config.ts points elsewhere would
  // have drizzle-kit write there while we search `drizzle/` and fail in step 2.
  // It defaults to `drizzle/`; override with `--out` to match your config.
  const { command, prefixArgs } = execArgv(pm)
  const drizzleArgs = [
    ...prefixArgs,
    'drizzle-kit',
    'generate',
    '--custom',
    `--name=${migrationName}`,
    `--out=${outDir}`,
  ]
  const displayCmd = `${execCommand(pm)} ${drizzleArgs.slice(prefixArgs.length).join(' ')}`

  // Load the SQL up front so a corrupt/missing bundle fails BEFORE we scaffold
  // anything (nothing to orphan), with the same spinner-free error the other
  // steps use rather than a raw fatal stack trace.
  let sql: string
  try {
    sql = buildEqlV3MigrationSql({ supabase: options.supabase ?? false })
  } catch (error) {
    p.log.error(error instanceof Error ? error.message : String(error))
    throw new CliExit(1)
  }

  const embedded = options.embedded ?? false
  if (!embedded) p.intro('CipherStash EQL migration')

  if (options.dryRun) {
    p.note(
      `Would run: ${displayCmd}\nWould write the EQL v3 install SQL${options.supabase ? ' (with Supabase grants)' : ''} into the generated migration in ${outDir}`,
      'Dry Run',
    )
    if (!embedded) p.outro('Dry run complete.')
    return
  }

  const s = p.spinner()

  // Step 1 — scaffold an empty custom migration (drizzle-kit owns the journal
  // + sequence numbering; hand-rolling that is fragile).
  s.start('Generating custom Drizzle migration...')
  const result = spawnSync(command, drizzleArgs, {
    stdio: 'pipe',
    encoding: 'utf-8',
  })
  if (result.status !== 0) {
    s.stop('Failed to generate migration.')
    const stderr = result.stderr?.trim()
    p.log.error(
      stderr ||
        result.error?.message ||
        `drizzle-kit exited with status ${result.status ?? 'unknown'}.`,
    )
    p.log.info(
      `Make sure drizzle-kit is installed and configured: ${execCommand(pm)} drizzle-kit --version`,
    )
    if (!embedded) p.outro('Migration aborted.')
    throw new CliExit(1)
  }
  s.stop('Custom Drizzle migration generated.')

  // Step 2 — locate the file drizzle-kit just wrote.
  let migrationPath: string
  s.start('Locating generated migration file...')
  try {
    migrationPath = await findGeneratedMigration(outDir, migrationName)
    s.stop(`Found migration: ${migrationPath}`)
  } catch (error) {
    s.stop('Failed to locate migration file.')
    p.log.error(error instanceof Error ? error.message : String(error))
    p.log.info(
      `If your drizzle.config.ts writes elsewhere, pass --out <dir> so it matches.`,
    )
    if (!embedded) p.outro('Migration aborted.')
    throw new CliExit(1)
  }

  // Step 3 — write the EQL v3 install SQL into it.
  s.start('Writing EQL v3 install SQL into migration file...')
  try {
    writeFileSync(migrationPath, sql, 'utf-8')
    s.stop('EQL v3 install SQL written.')
  } catch (error) {
    s.stop('Failed to write migration file.')
    p.log.error(error instanceof Error ? error.message : String(error))
    cleanupMigrationFile(migrationPath)
    if (!embedded) p.outro('Migration aborted.')
    throw new CliExit(1)
  }

  // Step 4 — sweep for sibling migrations drizzle-kit emitted with an in-place
  // `ALTER COLUMN ... SET DATA TYPE <encrypted domain>`. Those fail in Postgres
  // (no implicit cast from text/numeric to an EQL domain), so rewrite them into
  // a staged encrypted-column addition that preserves the source column.
  // Whether the sweep failed outright or left near-misses it couldn't rewrite,
  // the user must review sibling migrations before running migrate, so surface
  // it again at the closing note (below) — not just inline here.
  let sweepIncomplete = false
  try {
    const { rewritten, skipped, staged } = await rewriteEncryptedAlterColumns(
      outDir,
      { skip: migrationPath },
    )
    if (rewritten.length > 0) {
      p.log.info(
        `Rewrote ${rewritten.length} migration file(s) to add staged encrypted columns while preserving the source columns:`,
      )
      for (const file of rewritten) p.log.step(`  - ${file}`)
    }
    // The rewrite repaired SQL only, so schema.ts and the drizzle-kit snapshot
    // now disagree with the database — and `drizzle-kit generate` cannot see it
    // (#836, item 2). Warn, rather than exit non-zero: the swept SQL is valid
    // and additive, and the reconciliation is the user's editorial call.
    if (staged.length > 0) {
      p.log.warn(describeStagedReconciliation(staged).join('\n'))
    }
    if (skipped.length > 0) {
      sweepIncomplete = true
      p.log.warn(
        `Found ${skipped.length} ALTER-to-encrypted statement(s) the sweep left alone. Review and fix them before running your migrations:`,
      )
      for (const { file, statement, reason } of skipped) {
        p.log.step(`  - ${file}: ${statement}`)
        p.log.step(`      ${describeSkipReason(reason)}`)
      }
    }
  } catch (error) {
    // Advisory: the install migration itself is already written and valid.
    sweepIncomplete = true
    const partial: PartialRewriteResult = isPartialRewriteResult(error)
      ? error
      : {}
    if (partial.rewritten && partial.rewritten.length > 0) {
      p.log.info(
        `Rewrote ${partial.rewritten.length} migration file(s) before the sweep stopped:`,
      )
      for (const file of partial.rewritten) p.log.step(`  - ${file}`)
    }
    // A partial sweep still staged real twins, so the same three-way divergence
    // already exists for them.
    if (partial.staged && partial.staged.length > 0) {
      p.log.warn(describeStagedReconciliation(partial.staged).join('\n'))
    }
    if (partial.skipped && partial.skipped.length > 0) {
      p.log.warn(
        `Found ${partial.skipped.length} ALTER-to-encrypted statement(s) the sweep left alone. Review and fix them before running your migrations:`,
      )
      for (const { file, statement, reason } of partial.skipped) {
        p.log.step(`  - ${file}: ${statement}`)
        p.log.step(`      ${describeSkipReason(reason)}`)
      }
    }
    p.log.warn(
      `Could not sweep ${outDir} for unsafe ALTER COLUMN statements: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }

  if (sweepIncomplete) {
    p.log.error(
      `The ALTER COLUMN sweep found unsafe or unverified SQL. The generated migration remains at ${migrationPath}, but review the sibling migrations in ${outDir} and use the staged stash encrypt flow before running drizzle-kit migrate.`,
    )
    if (!embedded) p.outro('Migration aborted.')
    throw new CliExit(1)
  }
  p.log.success(`Migration created: ${migrationPath}`)
  p.note(
    `Run your Drizzle migrations to install EQL v3:\n\n  ${execCommand(pm)} drizzle-kit migrate`,
    'Next Steps',
  )
  if (!embedded) {
    printNextSteps()
    p.outro('Done!')
  }
}
