import { execSync } from 'node:child_process'
import { existsSync, unlinkSync, writeFileSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { loadStashConfig } from '@/config/index.js'
import {
  EQLInstaller,
  downloadEqlSql,
  loadBundledEqlSql,
} from '@/installer/index.js'
import {
  MIGRATIONS_SCHEMA_SQL,
  installMigrationsSchema,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { ensureStashConfig } from './config-scaffold.js'
import {
  type SupabaseProjectInfo,
  detectDrizzle,
  detectSupabase,
  detectSupabaseProject,
} from './detect.js'
import { rewriteEncryptedAlterColumns } from './rewrite-migrations.js'
import {
  SUPABASE_EQL_MIGRATION_FILENAME,
  writeSupabaseEqlMigration,
} from './supabase-migration.js'

const DEFAULT_MIGRATION_NAME = 'install-eql'
const DEFAULT_DRIZZLE_OUT = 'drizzle'

export interface InstallOptions {
  force?: boolean
  dryRun?: boolean
  /**
   * `undefined` means "auto-detect" (via {@link detectSupabase}). An explicit
   * `true`/`false` from the user is preserved and skips detection.
   */
  excludeOperatorFamily?: boolean
  supabase?: boolean
  drizzle?: boolean
  latest?: boolean
  name?: string
  out?: string
  /**
   * Write the EQL install SQL into a Supabase migration file instead of
   * running it directly against the database. Requires `--supabase`.
   */
  migration?: boolean
  /**
   * Run the EQL install SQL directly against the database (current behavior).
   * Requires `--supabase`. Mutually exclusive with `--migration`.
   */
  direct?: boolean
  /**
   * Override the directory the Supabase migration file is written into.
   * Defaults to `<cwd>/supabase/migrations`.
   */
  migrationsDir?: string
}

/** Resolved install mode for the Supabase non-Drizzle branch. */
export type SupabaseInstallMode = 'migration' | 'direct'

export async function installCommand(options: InstallOptions) {
  p.intro('npx @cipherstash/cli db install')

  // Validate mutually-exclusive / supabase-required flags BEFORE doing any
  // I/O. `--migration` and `--direct` only make sense in the Supabase flow;
  // they must NOT implicitly enable `--supabase`. (Strong product preference
  // — auto-enabling here has bitten users before.)
  const flagError = validateInstallFlags(options)
  if (flagError) {
    p.log.error(flagError)
    p.outro('Installation aborted.')
    process.exit(1)
  }

  // Scaffold stash.config.ts if missing. `db install` is the single command
  // that gets a project from zero to installed EQL — no separate setup step
  // (CIP-2986).
  const configReady = await ensureStashConfig()
  if (!configReady) {
    process.exit(0)
  }

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig()
  s.stop('Configuration loaded.')

  // Auto-detect provider hints when the user didn't explicitly pass flags.
  // CIP-2985.
  const resolved = resolveProviderOptions(options, config.databaseUrl)

  if (resolved.drizzle) {
    await generateDrizzleMigration(s, {
      name: options.name,
      out: options.out,
      dryRun: options.dryRun,
      latest: options.latest,
      supabase: resolved.supabase,
      excludeOperatorFamily: resolved.excludeOperatorFamily,
    })
    return
  }

  // Supabase non-Drizzle path: pick between writing a migration file and
  // running SQL directly. Detection of `supabase/migrations/` only seeds the
  // prompt default — it never enables `--supabase`. Direct install is the
  // historical default and remains the fallback when nothing else applies.
  if (resolved.supabase) {
    const projectInfo = detectSupabaseProject(
      process.cwd(),
      options.migrationsDir,
    )
    const mode = await resolveSupabaseInstallMode(options, projectInfo)

    if (mode === 'migration') {
      // CIP: --latest in the migration path is not yet implemented. Loading
      // the bundled SQL works today; downloading from GitHub adds an extra
      // moving part we'd rather defer until someone needs it.
      if (options.latest) {
        p.log.error(
          '`db install --supabase --migration --latest` is not yet supported. Please open an issue at https://github.com/cipherstash/stack/issues if you need this.',
        )
        p.outro('Installation aborted.')
        process.exit(1)
      }

      await writeSupabaseMigrationFile(s, {
        projectInfo,
        force: options.force,
        dryRun: options.dryRun,
      })
      return
    }
    // mode === 'direct' — fall through to existing direct-install behavior.
  }

  if (options.dryRun) {
    p.log.info('Dry run — no changes will be made.')
    const source = options.latest
      ? 'Would download EQL install script from GitHub'
      : 'Would use bundled EQL install script'
    p.note(`${source}\nWould execute the SQL against the database`, 'Dry Run')
    p.outro('Dry run complete.')
    return
  }

  const installer = new EQLInstaller({
    databaseUrl: config.databaseUrl,
  })

  s.start('Checking database permissions...')
  const permissions = await installer.checkPermissions()

  // CIP-2989: if the role is not a superuser and neither --supabase nor
  // --exclude-operator-family was passed, auto-fall back to the
  // no-operator-family (OPE) install variant. This is the same thing an
  // experienced user would do manually; doing it automatically avoids the
  // "what flag do I need?" failure mode on Supabase/Neon/RDS.
  let excludeOperatorFamily = resolved.excludeOperatorFamily
  if (
    !permissions.isSuperuser &&
    !resolved.supabase &&
    options.excludeOperatorFamily === undefined
  ) {
    excludeOperatorFamily = true
    s.stop(
      'Role lacks superuser — falling back to the no-operator-family (OPE) install.',
    )
  } else if (!permissions.ok) {
    s.stop('Insufficient database permissions.')
    p.log.error('The connected database role is missing required permissions:')
    for (const missing of permissions.missing) {
      p.log.warn(`  - ${missing}`)
    }
    p.note(
      'EQL installation requires a role with CREATE SCHEMA,\nCREATE TYPE, and CREATE EXTENSION privileges.\n\nConnect with a superuser or admin role, or ask your\ndatabase administrator to grant the required permissions.',
      'Required Permissions',
    )
    p.outro('Installation aborted.')
    process.exit(1)
  } else {
    s.stop('Database permissions verified.')
  }

  if (!options.force) {
    s.start('Checking if EQL is already installed...')
    const installed = await installer.isInstalled()
    s.stop(installed ? 'EQL is already installed.' : 'EQL is not installed.')

    if (installed) {
      p.log.info('Use --force to re-run the install script.')
      p.outro('Nothing to do.')
      return
    }
  }

  const source = options.latest ? 'from GitHub (latest)' : 'bundled'
  s.start(`Installing EQL extensions (${source})...`)
  await installer.install({
    excludeOperatorFamily,
    supabase: resolved.supabase,
    latest: options.latest,
  })
  s.stop('EQL extensions installed.')

  if (resolved.supabase) {
    p.log.success('Supabase role permissions granted.')
  }

  s.start('Installing cs_migrations tracking schema...')
  const migrationsDb = new pg.Client({ connectionString: config.databaseUrl })
  try {
    await migrationsDb.connect()
    await installMigrationsSchema(migrationsDb)
    s.stop('cs_migrations schema installed.')
  } catch (err) {
    s.stop('Failed to install cs_migrations schema.')
    p.log.warn(
      err instanceof Error
        ? err.message
        : 'Encryption migration tracking is unavailable; `stash encrypt` commands will fail until this is resolved.',
    )
  } finally {
    await migrationsDb.end()
  }

  printNextSteps()
  p.outro('Done!')
}

/**
 * Merge explicit CLI flags with auto-detected hints.
 *
 * Rules:
 * - `--supabase` explicitly passed wins.
 * - `--supabase` not passed → if the database URL looks like Supabase, enable it.
 * - `--drizzle` explicitly passed wins.
 * - `--drizzle` not passed → if drizzle-orm/drizzle-kit/drizzle.config.* exists, enable it.
 * - `--exclude-operator-family` explicitly passed wins.
 */
function resolveProviderOptions(
  options: InstallOptions,
  databaseUrl: string,
): {
  supabase: boolean
  drizzle: boolean
  excludeOperatorFamily: boolean
} {
  const supabase =
    options.supabase === undefined
      ? detectSupabase(databaseUrl)
      : options.supabase
  if (options.supabase === undefined && supabase) {
    p.log.info(
      'Detected Supabase database from DATABASE_URL — enabling --supabase.',
    )
  }

  const drizzle =
    options.drizzle === undefined
      ? detectDrizzle(process.cwd())
      : options.drizzle
  if (options.drizzle === undefined && drizzle) {
    p.log.info('Detected Drizzle in this project — enabling --drizzle.')
  }

  const excludeOperatorFamily = options.excludeOperatorFamily ?? false

  return { supabase, drizzle, excludeOperatorFamily }
}

function printNextSteps(): void {
  p.note(
    [
      'Next steps:',
      '',
      '  1. Wire up encrypt/decrypt with the wizard:',
      '       npx @cipherstash/cli wizard',
      '',
      '  2. Or use the client directly from @cipherstash/stack:',
      "       import { Encryption } from '@cipherstash/stack'",
      '       const client = await Encryption({ /* ... */ })',
      '       await client.encryptModel(record, table).run()',
      '',
      '  3. Docs: https://cipherstash.com/docs',
    ].join('\n'),
    'What next',
  )
}

/**
 * Generate a Drizzle migration that installs CipherStash EQL.
 *
 * Uses `drizzle-kit generate --custom` to scaffold an empty migration,
 * then loads the EQL install SQL (bundled by default, or from GitHub with
 * `--latest`) and writes it into the file.
 */
async function generateDrizzleMigration(
  s: ReturnType<typeof p.spinner>,
  options: {
    name?: string
    out?: string
    dryRun?: boolean
    latest?: boolean
    supabase?: boolean
    excludeOperatorFamily?: boolean
  },
) {
  const migrationName = options.name ?? DEFAULT_MIGRATION_NAME
  const outDir = resolve(options.out ?? DEFAULT_DRIZZLE_OUT)

  if (options.dryRun) {
    p.log.info('Dry run — no changes will be made.')
    const source = options.latest
      ? 'Would download EQL install SQL from GitHub'
      : 'Would use bundled EQL install SQL'
    p.note(
      `Would run: npx drizzle-kit generate --custom --name=${migrationName}\n${source}\nWould write SQL to migration file in ${outDir}`,
      'Dry Run',
    )
    p.outro('Dry run complete.')
    return
  }

  let generatedMigrationPath: string | undefined

  // Step 1: Generate a custom Drizzle migration
  s.start('Generating custom Drizzle migration...')

  try {
    execSync(`npx drizzle-kit generate --custom --name=${migrationName}`, {
      stdio: 'pipe',
      encoding: 'utf-8',
    })
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
    if (stderr) {
      p.log.error(stderr)
    } else {
      p.log.error(
        error instanceof Error ? error.message : 'Unknown error occurred.',
      )
    }
    p.log.info('Make sure drizzle-kit is installed: npm install -D drizzle-kit')
    p.outro('Migration aborted.')
    process.exit(1)
  }

  // Step 2: Find the generated migration file
  s.start('Locating generated migration file...')

  try {
    generatedMigrationPath = await findGeneratedMigration(outDir, migrationName)
    s.stop(`Found migration: ${generatedMigrationPath}`)
  } catch (error) {
    s.stop('Failed to locate migration file.')
    p.log.error(error instanceof Error ? error.message : String(error))
    p.outro('Migration aborted.')
    process.exit(1)
  }

  // Step 3: Load the EQL SQL (bundled or from GitHub). Thread supabase /
  // excludeOperatorFamily through so the user's flag reaches the SQL
  // selection — previously this path ignored both (CIP-2988).
  let eqlSql: string
  const sqlOptions = {
    supabase: options.supabase ?? false,
    excludeOperatorFamily: options.excludeOperatorFamily ?? false,
  }

  if (options.latest) {
    s.start('Downloading EQL install script from GitHub (latest)...')
    try {
      eqlSql = await downloadEqlSql(sqlOptions)
      s.stop('EQL install script downloaded.')
    } catch (error) {
      s.stop('Failed to download EQL install script.')
      p.log.error(error instanceof Error ? error.message : String(error))
      cleanupMigrationFile(generatedMigrationPath)
      p.outro('Migration aborted.')
      process.exit(1)
    }
  } else {
    s.start('Loading bundled EQL install script...')
    try {
      eqlSql = loadBundledEqlSql(sqlOptions)
      s.stop('Bundled EQL install script loaded.')
    } catch (error) {
      s.stop('Failed to load bundled EQL install script.')
      p.log.error(error instanceof Error ? error.message : String(error))
      cleanupMigrationFile(generatedMigrationPath)
      p.outro('Migration aborted.')
      process.exit(1)
    }
  }

  // Step 4: Write the EQL SQL (and cs_migrations tracking schema) into
  // the migration file. Bundling both means `drizzle-kit migrate` rolls
  // everything needed for `stash encrypt ...` out to each environment
  // in one go, rather than requiring an out-of-band `stash db install`.
  s.start('Writing EQL SQL into migration file...')

  const migrationContents = `${eqlSql}\n\n-- CipherStash encryption-migration tracking schema.\n-- Tracks per-column phase + backfill progress for \`stash encrypt\`.\n${MIGRATIONS_SCHEMA_SQL.trim()}\n`

  try {
    writeFileSync(generatedMigrationPath, migrationContents, 'utf-8')
    s.stop('EQL SQL written to migration file.')
  } catch (error) {
    s.stop('Failed to write migration file.')
    p.log.error(error instanceof Error ? error.message : String(error))
    cleanupMigrationFile(generatedMigrationPath)
    p.outro('Migration aborted.')
    process.exit(1)
  }

  // Step 5: Sweep for sibling migrations that drizzle-kit may have emitted
  // with `ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted`. These fail in
  // Postgres because there's no implicit cast from text/numeric to the
  // encrypted type. Rewrite them into the ADD/UPDATE/DROP/RENAME sequence
  // that works on both empty and populated tables. CIP-2991 + CIP-2994.
  try {
    const rewritten = await rewriteEncryptedAlterColumns(outDir, {
      skip: generatedMigrationPath,
    })
    if (rewritten.length > 0) {
      p.log.info(
        `Rewrote ${rewritten.length} migration file(s) to use safe ADD+migrate+DROP for encrypted columns:`,
      )
      for (const file of rewritten) p.log.step(`  - ${file}`)
    }
  } catch (error) {
    p.log.warn(
      `Could not rewrite ALTER COLUMN migrations: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  p.log.success(`Migration created: ${generatedMigrationPath}`)
  p.note(
    'Run your Drizzle migrations to install EQL:\n\n  npx drizzle-kit migrate',
    'Next Steps',
  )
  printNextSteps()
  p.outro('Done!')
}

/**
 * Validate flag combinations that we can detect without doing any I/O.
 *
 * Rules:
 *   - `--migration` and `--direct` are mutually exclusive.
 *   - `--migration`, `--direct`, and `--migrations-dir` each REQUIRE
 *     `--supabase`. They do NOT auto-imply it.
 *
 * Returns a user-facing error message, or `null` when the flags are valid.
 */
export function validateInstallFlags(options: InstallOptions): string | null {
  if (options.migration && options.direct) {
    return '`--migration` and `--direct` are mutually exclusive. Pick one.'
  }

  const subFlag =
    options.migration === true
      ? '--migration'
      : options.direct === true
        ? '--direct'
        : options.migrationsDir !== undefined
          ? '--migrations-dir'
          : null

  if (subFlag !== null && options.supabase !== true) {
    return `\`${subFlag}\` requires \`--supabase\`. Re-run with \`db install --supabase ${subFlag}\`.`
  }

  return null
}

/**
 * Pick the Supabase install mode purely from inputs. No I/O, no prompts —
 * easy to unit-test and to reason about.
 *
 * - Explicit `--migration` or `--direct` always wins.
 * - Otherwise, when stdin isn't a TTY, default to `migration` if the
 *   `supabase/migrations/` directory exists and `direct` otherwise. This is
 *   the same heuristic the prompt uses for its default — keeps interactive
 *   and non-interactive runs aligned.
 * - When stdin IS a TTY and neither flag is set, returns `null` to signal
 *   that the caller should prompt.
 */
export function chooseSupabaseInstallMode(
  options: Pick<InstallOptions, 'migration' | 'direct'>,
  projectInfo: SupabaseProjectInfo,
  isTTY: boolean,
): SupabaseInstallMode | null {
  if (options.migration) return 'migration'
  if (options.direct) return 'direct'
  if (!isTTY) return projectInfo.hasMigrationsDir ? 'migration' : 'direct'
  return null
}

/**
 * Resolve the install mode, prompting the user when stdin is a TTY and
 * neither sub-flag was passed. Pure logic lives in
 * {@link chooseSupabaseInstallMode}; this is the I/O wrapper.
 */
async function resolveSupabaseInstallMode(
  options: InstallOptions,
  projectInfo: SupabaseProjectInfo,
): Promise<SupabaseInstallMode> {
  const isTTY = Boolean(process.stdin.isTTY) && process.env.CI !== 'true'
  const decided = chooseSupabaseInstallMode(options, projectInfo, isTTY)

  if (decided !== null) {
    if (
      !isTTY &&
      options.migration === undefined &&
      options.direct === undefined
    ) {
      // Make non-interactive choices visible — surprise auto-decisions are a
      // common debugging headache.
      p.log.info(
        projectInfo.hasMigrationsDir
          ? `Detected ${projectInfo.migrationsDir} — defaulting to --migration in non-interactive mode.`
          : 'No supabase/migrations directory found — defaulting to --direct in non-interactive mode.',
      )
    }
    return decided
  }

  const defaultMode: SupabaseInstallMode = projectInfo.hasMigrationsDir
    ? 'migration'
    : 'direct'

  const choice = await p.select<SupabaseInstallMode>({
    message: 'How should EQL be installed?',
    initialValue: defaultMode,
    options: [
      {
        value: 'migration',
        label: 'Write a Supabase migration file',
        hint: projectInfo.hasMigrationsDir
          ? 'recommended — works with `supabase db reset`'
          : 'creates supabase/migrations/ if missing',
      },
      {
        value: 'direct',
        label: 'Run the SQL directly against the database',
        hint: 'fastest, but `supabase db reset` will not re-install EQL',
      },
    ],
  })

  if (p.isCancel(choice)) {
    p.cancel('Installation cancelled.')
    process.exit(0)
  }

  return choice
}

/**
 * Write the `00000000000000_cipherstash_eql.sql` migration to the project's
 * Supabase migrations directory. Mirrors the structure of the Drizzle
 * migration helper for parity in the user-facing flow.
 */
async function writeSupabaseMigrationFile(
  s: ReturnType<typeof p.spinner>,
  opts: {
    projectInfo: SupabaseProjectInfo
    force?: boolean
    dryRun?: boolean
  },
): Promise<void> {
  const { projectInfo, force, dryRun } = opts
  const targetPath = join(
    projectInfo.migrationsDir,
    SUPABASE_EQL_MIGRATION_FILENAME,
  )

  if (dryRun) {
    p.log.info('Dry run — no changes will be made.')
    p.note(
      [
        `Would write Supabase migration to:\n  ${targetPath}`,
        '',
        'Apply with one of:',
        '  supabase db reset       # local',
        '  supabase migration up   # remote (or push)',
      ].join('\n'),
      'Dry Run',
    )
    p.outro('Dry run complete.')
    return
  }

  s.start('Writing CipherStash EQL migration...')
  let result: { path: string; overwritten: boolean }
  try {
    result = await writeSupabaseEqlMigration({
      migrationsDir: projectInfo.migrationsDir,
      force,
    })
  } catch (error) {
    s.stop('Failed to write Supabase migration.')
    const message = error instanceof Error ? error.message : String(error)
    p.log.error(message)
    if (!force && message.includes('already exists')) {
      p.log.info(
        'Re-run with --force to overwrite the existing migration file.',
      )
    }
    p.outro('Installation aborted.')
    process.exit(1)
  }

  s.stop(
    result.overwritten
      ? `Overwrote ${result.path}`
      : `Migration created: ${result.path}`,
  )

  p.note(
    [
      'Apply the migration to install EQL:',
      '',
      '  supabase db reset       # local — re-runs all migrations',
      '  supabase migration up   # remote — applies pending migrations',
      '',
      'EQL is NOT installed yet. The SQL only runs when Supabase applies the migration.',
    ].join('\n'),
    'Next Steps',
  )
  printNextSteps()
  p.outro('Done!')
}

/**
 * Find the most recently generated migration file matching the given name.
 * Drizzle-kit generates flat SQL files like `0000_install-eql.sql`.
 */
async function findGeneratedMigration(
  outDir: string,
  migrationName: string,
): Promise<string> {
  if (!existsSync(outDir)) {
    throw new Error(
      `Drizzle output directory not found: ${outDir}\nMake sure drizzle-kit is configured correctly.`,
    )
  }

  const entries = await readdir(outDir)

  const matchingFiles = entries
    .filter((entry) => entry.endsWith('.sql') && entry.includes(migrationName))
    .sort()

  if (matchingFiles.length === 0) {
    throw new Error(
      `Could not find a migration matching "${migrationName}" in ${outDir}`,
    )
  }

  return join(outDir, matchingFiles[matchingFiles.length - 1])
}

/**
 * Attempt to clean up a generated migration file on failure.
 */
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
