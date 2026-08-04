import { spawnSync } from 'node:child_process'
import { existsSync, unlinkSync, writeFileSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { MIGRATIONS_SCHEMA_SQL } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { CliExit } from '@/cli/exit.js'
import { detectSupabaseProject } from '@/commands/db/detect.js'
import { printNextSteps, SAFE_MIGRATION_NAME } from '@/commands/db/install.js'
import { rewriteEncryptedAlterColumns } from '@/commands/db/rewrite-migrations.js'
import {
  findExistingEqlMigration,
  writeSupabaseEqlMigration,
} from '@/commands/eql/supabase-migration.js'
import {
  reportSweepFailure,
  reportSweepResult,
} from '@/commands/eql/sweep-report.js'
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
  /**
   * Two roles, decided by whether another target is present:
   *
   * - alone, it IS the target — write the install into `supabase/migrations/`;
   * - with `--drizzle`, it's a modifier that appends the Supabase role grants
   *   (`eql_v3` + `eql_v3_internal`) to the Drizzle migration.
   *
   * The grants are in the emitted SQL either way; only the destination differs.
   */
  supabase?: boolean
  /** Migration name (Drizzle). Defaults to `install-eql`. */
  name?: string
  /**
   * Output directory: where drizzle-kit writes under `--drizzle` (default
   * `drizzle`), or the migrations directory under `--supabase` (default
   * `supabase/migrations`).
   */
  out?: string
  /**
   * Write a Supabase install migration even though one is already there.
   * Drizzle doesn't need this — drizzle-kit numbers each generated migration,
   * so a re-run never collides.
   */
  force?: boolean
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
 * ORM or platform, rather than running SQL directly against the database
 * (that's `stash eql install`). Migration-first is the preferred path: the
 * install lands in the project's migration history and ships to every
 * environment through that project's own migrate step.
 *
 * Two emitters, one SQL body ({@link buildEqlV3MigrationSql}):
 *
 * - `--drizzle` scaffolds through drizzle-kit so the migration is journaled;
 * - `--supabase` (alone) writes into `supabase/migrations/`, which is what
 *   makes the install survive `supabase db reset` — a reset drops the database
 *   and replays that directory, so a direct install is wiped by it.
 *
 * `--supabase` alongside `--drizzle` is NOT a second target: it's the grants
 * modifier for a Supabase-hosted Drizzle project. Only a bare `--supabase`
 * selects the Supabase emitter.
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
  if (options.drizzle && options.prisma) {
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

  if (options.drizzle) {
    await generateDrizzleEqlMigration(options)
    return
  }

  if (options.supabase) {
    await generateSupabaseEqlMigration(options)
    return
  }

  p.log.error(messages.eql.migrationNeedsTarget)
  throw new CliExit(1)
}

/**
 * Write the EQL v3 install into `supabase/migrations/`.
 *
 * Deliberately unlike the Drizzle path in two ways. There is no drizzle-kit to
 * scaffold through — Supabase migrations are plain timestamped `.sql` files
 * with no journal to keep in step, so we write the file ourselves. And there is
 * no ALTER COLUMN sweep: that exists because `drizzle-kit generate` emits
 * in-place type changes that cannot run, and nothing here generates SQL from a
 * schema diff.
 */
async function generateSupabaseEqlMigration(
  options: EqlMigrationOptions,
): Promise<void> {
  // Reuses the resolver that already knows the `supabase/migrations` default
  // and how to resolve a relative --out against the cwd.
  const { migrationsDir } = detectSupabaseProject(process.cwd(), options.out)

  // The filename is fixed (`<timestamp>_cipherstash_eql.sql`) because
  // `findExistingEqlMigration` matches on that suffix to refuse duplicates.
  // Silently dropping --name would leave the user believing they renamed it.
  if (options.name !== undefined) {
    p.log.warn(messages.eql.migrationNameDrizzleOnly)
  }

  // Load the SQL up front so a corrupt/missing bundle fails BEFORE we create
  // any directory, with the same spinner-free error the Drizzle path uses.
  let sql: string
  try {
    // Always with grants: a file written for Supabase is applied by Supabase,
    // where PostgREST reaches these tables as anon/authenticated/service_role.
    sql = buildEqlV3MigrationSql({ supabase: true })
  } catch (error) {
    p.log.error(error instanceof Error ? error.message : String(error))
    throw new CliExit(1)
  }

  const embedded = options.embedded ?? false
  if (!embedded) p.intro('CipherStash EQL migration')

  if (options.dryRun) {
    // Predict the real run's outcome, including its refusals — a dry run that
    // always claims "would write" is worse than no dry run in the one directory
    // where the answer is actually interesting.
    const existing = findExistingEqlMigration(migrationsDir)
    let preview: string
    if (!existing) {
      preview = `Would write the EQL v3 install SQL (with Supabase grants) into a new <timestamp>_cipherstash_eql.sql in ${migrationsDir}`
    } else if (options.force) {
      preview = `Would replace the EQL v3 install SQL in ${existing}, keeping its version.`
    } else {
      preview = `Would refuse: an EQL install migration already exists at ${existing}. Re-run with --force to replace it, or delete that file first.`
    }
    p.note(preview, 'Dry Run')
    if (!embedded) p.outro('Dry run complete.')
    return
  }

  const s = p.spinner()
  s.start('Writing EQL v3 install migration...')
  let written: Awaited<ReturnType<typeof writeSupabaseEqlMigration>>
  try {
    written = await writeSupabaseEqlMigration({
      migrationsDir,
      sql,
      force: options.force ?? false,
    })
    // Status only — the path is reported once, by the success line below, the
    // same shape the Drizzle path uses.
    s.stop('EQL v3 install SQL written.')
  } catch (error) {
    s.stop('Failed to write the migration.')
    p.log.error(error instanceof Error ? error.message : String(error))
    if (!embedded) p.outro('Migration aborted.')
    throw new CliExit(1)
  }

  if (written.overwritten) {
    // Rewriting a migration that some database has already applied leaves the
    // file describing a shape that database never got from it — the same
    // hazard `eql repair` guards against. We can't check that from here (no
    // connection), so say it plainly. Lead with the reset: this is the local
    // case, and it is the path the Supabase docs steer people to.
    p.log.warn(
      'Replaced the existing EQL install migration in place, keeping its version. Any database that already applied it still has the old bundle — re-apply with `supabase db reset` (local) or `supabase db push` (remote).',
    )
  }

  p.log.success(
    `Migration ${written.overwritten ? 'replaced' : 'created'}: ${written.path}`,
  )
  p.note(
    `Apply it:\n\n  supabase db reset               # local — replays every migration\n  supabase db push                # remote/linked project`,
    'Next Steps',
  )
  if (!embedded) {
    printNextSteps()
    p.outro('Done!')
  }
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
    sweepIncomplete = reportSweepResult(
      await rewriteEncryptedAlterColumns(outDir, { skip: migrationPath }),
    )
  } catch (error) {
    // Advisory: the install migration itself is already written and valid.
    sweepIncomplete = true
    reportSweepFailure(outDir, error)
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
