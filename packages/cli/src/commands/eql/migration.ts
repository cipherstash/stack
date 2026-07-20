import { spawnSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { MIGRATIONS_SCHEMA_SQL } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { CliExit } from '@/cli/exit.js'
import {
  cleanupMigrationFile,
  findGeneratedMigration,
  printNextSteps,
  SAFE_MIGRATION_NAME,
} from '@/commands/db/install.js'
import {
  detectPackageManager,
  execArgv,
  execCommand,
} from '@/commands/init/utils.js'
import { loadBundledEqlSql, supabaseGrantsFor } from '@/installer/index.js'
import { messages } from '@/messages.js'

const DEFAULT_MIGRATION_NAME = 'install-eql'
const DEFAULT_DRIZZLE_OUT = 'drizzle'

export interface EqlMigrationOptions {
  /** Emit a Drizzle custom migration. */
  drizzle?: boolean
  /** Emit a Prisma Next migration (not yet available — see issue #690). */
  prisma?: boolean
  /** Append the Supabase role grants (`eql_v3` + `eql_v3_internal`). */
  supabase?: boolean
  /** Migration name (Drizzle). Defaults to `install-eql`. */
  name?: string
  /** Output directory (Drizzle). Defaults to `drizzle`. */
  out?: string
  /** Describe what would happen without writing anything. */
  dryRun?: boolean
}

/**
 * Assemble the EQL **v3** install SQL for a generated migration.
 *
 * One source of truth: the SQL is the CLI's bundled v3 install script
 * (`loadBundledEqlSql({ eqlVersion: 3 })`) — the same bundle `stash eql install`
 * applies directly. On `--supabase` the v3 role grants are appended
 * (`supabaseGrantsFor(3)` → USAGE/EXECUTE on `eql_v3` + `eql_v3_internal` for
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
  const eqlSql = loadBundledEqlSql({ eqlVersion: 3 })
  const grants = opts.supabase
    ? `\n\n-- Supabase role grants: let anon/authenticated/service_role use the\n-- eql_v3 + eql_v3_internal schemas (required when tables are reached via\n-- PostgREST/RLS; harmless otherwise).\n${supabaseGrantsFor(3).trim()}`
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
    // The Prisma Next emitter is a follow-up (tracked in #690): it will write
    // the install migration in the framework `Migration` shape and let
    // prisma-next drop its baked install baseline. Until it lands, fail loudly
    // with a pointer rather than emit a broken/empty file.
    p.log.error(messages.eql.migrationPrismaUnavailable)
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

  p.intro('CipherStash EQL migration')

  if (options.dryRun) {
    p.note(
      `Would run: ${displayCmd}\nWould write the EQL v3 install SQL${options.supabase ? ' (with Supabase grants)' : ''} into the generated migration in ${outDir}`,
      'Dry Run',
    )
    p.outro('Dry run complete.')
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
    p.outro('Migration aborted.')
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
    p.outro('Migration aborted.')
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
    p.outro('Migration aborted.')
    throw new CliExit(1)
  }

  p.log.success(`Migration created: ${migrationPath}`)
  p.note(
    `Run your Drizzle migrations to install EQL v3:\n\n  ${execCommand(pm)} drizzle-kit migrate`,
    'Next Steps',
  )
  printNextSteps()
  p.outro('Done!')
}
