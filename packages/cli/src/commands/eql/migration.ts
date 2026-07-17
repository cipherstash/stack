import { execSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { MIGRATIONS_SCHEMA_SQL } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import {
  cleanupMigrationFile,
  findGeneratedMigration,
} from '@/commands/db/install.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
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
 * The `cs_migrations` tracking schema is bundled in so a single migration run
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
    process.exit(1)
  }
  if (targets.length > 1) {
    p.log.error(messages.eql.migrationOneTarget)
    process.exit(1)
  }

  if (options.prisma) {
    // The prisma-next emitter ships stacked on the prisma-next EQL v3 work
    // (PR #655); it can't install a v3 schema that doesn't exist on that
    // surface yet. Fail loudly with a pointer rather than emit a broken file.
    p.log.error(messages.eql.migrationPrismaUnavailable)
    process.exit(1)
  }

  await generateDrizzleEqlMigration(options)
}

async function generateDrizzleEqlMigration(
  options: EqlMigrationOptions,
): Promise<void> {
  const migrationName = options.name ?? DEFAULT_MIGRATION_NAME
  const outDir = resolve(options.out ?? DEFAULT_DRIZZLE_OUT)
  const runner = runnerCommand(detectPackageManager(), '').trim()
  const drizzleCmd = `${runner} drizzle-kit generate --custom --name=${migrationName}`

  const sql = buildEqlV3MigrationSql({ supabase: options.supabase ?? false })

  if (options.dryRun) {
    p.note(
      `Would run: ${drizzleCmd}\nWould write the EQL v3 install SQL${options.supabase ? ' (with Supabase grants)' : ''} into the generated migration in ${outDir}`,
      'Dry Run',
    )
    p.outro('Dry run complete.')
    return
  }

  const s = p.spinner()

  // Step 1 — scaffold an empty custom migration (drizzle-kit owns the journal
  // + sequence numbering; hand-rolling that is fragile).
  s.start('Generating custom Drizzle migration...')
  try {
    execSync(drizzleCmd, { stdio: 'pipe', encoding: 'utf-8' })
    s.stop('Custom Drizzle migration generated.')
  } catch (error) {
    s.stop('Failed to generate migration.')
    const stderr =
      error !== null &&
      typeof error === 'object' &&
      'stderr' in error &&
      typeof error.stderr === 'string'
        ? error.stderr.trim()
        : undefined
    p.log.error(
      stderr || (error instanceof Error ? error.message : 'Unknown error.'),
    )
    p.log.info('Make sure drizzle-kit is installed: npm install -D drizzle-kit')
    p.outro('Migration aborted.')
    process.exit(1)
  }

  // Step 2 — locate the file drizzle-kit just wrote.
  let migrationPath: string
  s.start('Locating generated migration file...')
  try {
    migrationPath = await findGeneratedMigration(outDir, migrationName)
    s.stop(`Found migration: ${migrationPath}`)
  } catch (error) {
    s.stop('Failed to locate migration file.')
    p.log.error(error instanceof Error ? error.message : String(error))
    p.outro('Migration aborted.')
    process.exit(1)
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
    process.exit(1)
  }

  p.log.success(`Migration created: ${migrationPath}`)
  p.note(
    `Run your Drizzle migrations to install EQL v3:\n\n  ${runner} drizzle-kit migrate`,
    'Next Steps',
  )
  p.outro('Done!')
}
