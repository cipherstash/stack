import { execSync } from 'node:child_process'
import { existsSync, unlinkSync, writeFileSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import {
  installMigrationsSchema,
  MIGRATIONS_SCHEMA_SQL,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { resolveDatabaseUrl } from '@/config/database-url.js'
import { findConfigFile, loadStashConfig } from '@/config/index.js'
import { isInteractive } from '@/config/tty.js'
import {
  downloadEqlSql,
  EQLInstaller,
  loadBundledEqlSql,
  resolveEqlVersion,
} from '@/installer/index.js'
import { messages } from '@/messages.js'
import { ensureEncryptionClient } from './client-scaffold.js'
import { offerStashConfig } from './config-scaffold.js'
import {
  detectDrizzle,
  detectPrismaNext,
  detectSupabase,
  detectSupabaseProject,
  type SupabaseProjectInfo,
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
  /**
   * Connection string passed via `--database-url`. Used for this run only —
   * never persisted. See `src/config/database-url.ts`.
   */
  databaseUrl?: string
  /**
   * How to handle a missing `stash.config.ts` — the caller owns this intent
   * rather than it being inferred from whether a URL was supplied:
   *  - `'ensure'` — create it without asking (`stash init`, where the user has
   *    already committed to setting the project up).
   *  - `'offer'`  — offer to create it (plain `stash eql install`). Default.
   *  - `'skip'`   — never scaffold (a one-shot `eql install --database-url ...`).
   */
  scaffoldConfig?: 'ensure' | 'offer' | 'skip'
  /**
   * EQL generation to install: `'3'` (default, native `eql_v3.*` domain
   * schema) or `'2'` (composite `eql_v2_encrypted`). v3 currently supports the
   * direct install path only — `--drizzle`, `--migration`, `--migrations-dir`,
   * and `--latest` require an explicit `'2'`.
   */
  eqlVersion?: string
}

/** Resolved install mode for the Supabase non-Drizzle branch. */
export type SupabaseInstallMode = 'migration' | 'direct'

/**
 * Resolve the database URL + encryption-client path for the install.
 *
 * A pre-existing `stash.config.ts` is authoritative — later workflow commands
 * (db push / schema build / encrypt) load the client through it — so we load
 * it. Without one, `eql install` doesn't need a config: resolve the URL
 * directly (flag → env → supabase → prompt). Decoupling install from the config
 * is what lets `npx stash eql install --database-url ...` run in a bare project
 * without the `stash` / `@cipherstash/stack` dependencies the config would
 * otherwise import (#579).
 *
 * Whether a missing config gets scaffolded is the caller's explicit intent
 * ({@link InstallOptions.scaffoldConfig}), not inferred from whether a URL was
 * supplied — `stash init` passes a resolved URL but still wants a config, while
 * a one-shot `--database-url` run wants the project left untouched. When no
 * config is created, `clientPath` comes back `null` so the caller skips the
 * client scaffold too.
 *
 * A one-shot run (`mode === 'skip'`, set when `--database-url` is passed alone)
 * bypasses config loading entirely: it must leave the project untouched, so it
 * neither honours nor scaffolds a config or client. This also means the flag
 * always wins — loading a config here could pick up a parent-directory config
 * with a hand-edited literal `databaseUrl` that silently overrides the flag and
 * installs EQL against the wrong database.
 */
async function resolveInstallContext(
  options: InstallOptions,
  s: ReturnType<typeof p.spinner>,
): Promise<{ databaseUrl: string; clientPath: string | null }> {
  const mode = options.scaffoldConfig ?? 'offer'

  // A one-shot `--database-url` install leaves the project untouched: don't load
  // an existing config (see doc comment re: parent-dir literal override) and
  // don't scaffold. Resolve the URL directly and return a null clientPath.
  const configPath = mode === 'skip' ? null : findConfigFile(process.cwd())
  if (configPath) {
    s.start('Loading stash.config.ts...')
    // Pass the path we already located so loadStashConfig doesn't re-walk the
    // filesystem to find it.
    const config = await loadStashConfig(
      {
        databaseUrlFlag: options.databaseUrl,
        supabase: options.supabase,
      },
      configPath,
    )
    s.stop('Configuration loaded.')

    // A config with a hand-edited literal `databaseUrl` bypasses the resolver,
    // so a `--database-url` flag would be silently ignored. Surface it rather
    // than installing against a different database than the user asked for —
    // especially since `findConfigFile` walks up into parent directories.
    if (
      options.databaseUrl !== undefined &&
      config.databaseUrl !== options.databaseUrl.trim()
    ) {
      p.log.warn(
        `Ignoring --database-url: ${configPath} sets an explicit databaseUrl that takes precedence. Installing against the config's database.`,
      )
    }
    return { databaseUrl: config.databaseUrl, clientPath: config.client }
  }

  const databaseUrl = await resolveDatabaseUrl({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })

  // A dry run must not write scaffold files, so it never enters the scaffold
  // path (nor does an explicit `skip`).
  if (mode === 'skip' || options.dryRun) {
    return { databaseUrl, clientPath: null }
  }

  const clientPath = await offerStashConfig({ ensure: mode === 'ensure' })
  return { databaseUrl, clientPath }
}

export async function installCommand(options: InstallOptions) {
  p.intro(runnerCommand(detectPackageManager(), 'stash eql install'))

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

  // Prisma Next owns EQL installation via its own migration system, so the
  // standalone installer is the wrong tool here. Refuse (before any DB I/O)
  // unless --force. Fires fast so a user who typed the wrong command gets a
  // pointer, not a half-applied install.
  const prismaNextBlock = prismaNextInstallGuard(process.cwd(), options)
  if (prismaNextBlock) {
    p.log.error(prismaNextBlock)
    p.outro('Installation aborted.')
    process.exit(1)
  }

  const s = p.spinner()

  // `eql install` only needs a database URL to install EQL. It does NOT require
  // a stash.config.ts: an existing config is authoritative (later workflow
  // commands rely on it), but without one we resolve the URL directly — so a
  // standalone `npx stash eql install --database-url ...` works with zero
  // project dependencies. A one-shot `--database-url` run leaves the project
  // untouched; otherwise we offer to scaffold a config for the rest of the
  // workflow (CIP-2986 / #579).
  const { databaseUrl, clientPath } = await resolveInstallContext(options, s)

  // Safety net: if the user ran `eql install` without first running `init`,
  // scaffold the encryption client file so clientPath points somewhere real.
  // No-op when the file already exists. Skipped for a one-shot `--database-url`
  // install (clientPath === null) or a dry run, which leave the project
  // untouched — an existing config still yields a clientPath, so guard on dryRun
  // too.
  if (clientPath && !options.dryRun) {
    ensureEncryptionClient(clientPath, process.cwd(), databaseUrl)
  }

  // Auto-detect provider hints when the user didn't explicitly pass flags.
  // CIP-2985.
  const resolved = resolveProviderOptions(options, databaseUrl)

  const eqlVersion: 2 | 3 = resolveEqlVersion(options.eqlVersion)

  // v3 supports the direct install path only. Explicit --drizzle/--migration
  // are rejected up-front by validateInstallFlags; auto-DETECTED drizzle or
  // migration modes fall back to direct here rather than erroring.
  const routing = routeInstallPathForEqlVersion(eqlVersion, resolved)
  if (routing.notice) {
    p.log.info(routing.notice)
  }

  if (routing.drizzle) {
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
  // v3 skips the mode selection entirely: direct install only for now.
  if (routing.useSupabaseInstallModeSelection) {
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
          '`eql install --supabase --migration --latest` is not yet supported. Please open an issue at https://github.com/cipherstash/stack/issues if you need this.',
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
      : `Would use bundled EQL${eqlVersion === 3 ? ' v3' : ''} install script`
    p.note(`${source}\nWould execute the SQL against the database`, 'Dry Run')
    p.outro('Dry run complete.')
    return
  }

  const installer = new EQLInstaller({
    databaseUrl,
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
    const installed = await installer.isInstalled({ eqlVersion })
    s.stop(installed ? 'EQL is already installed.' : 'EQL is not installed.')

    if (installed) {
      p.log.info('Use --force to re-run the install script.')
      p.outro('Nothing to do.')
      return
    }
  }

  const source = options.latest ? 'from GitHub (latest)' : 'bundled'
  s.start(
    `Installing EQL ${eqlVersion === 3 ? 'v3 ' : ''}extensions (${source})...`,
  )
  await installer.install({
    excludeOperatorFamily,
    supabase: resolved.supabase,
    latest: options.latest,
    eqlVersion,
  })
  s.stop('EQL extensions installed.')

  if (resolved.supabase) {
    p.log.success('Supabase role permissions granted.')
  }

  s.start('Installing cs_migrations tracking schema...')
  const migrationsDb = new pg.Client({ connectionString: databaseUrl })
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
      'Your project is set up. To encrypt your first column, pick the path',
      'that fits and ask your agent (the one `stash init` handed off to,',
      'or whichever agent you use):',
      '',
      '  Migrate an existing populated column (preserves live data):',
      '    Ask: "Use the stash lifecycle to encrypt <table>.<column>."',
      '',
      '  Add a new encrypted column from scratch (no plaintext predecessor):',
      '    Ask: "Add an encrypted <column> to <table>."',
      '',
      'The agent will edit your schema, generate the migration, wire the',
      'application code, and run the relevant `stash encrypt` commands.',
      'Reference: the stash-encryption / stash-cli skills (loaded in your',
      "agent's workspace) and https://cipherstash.com/docs.",
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
  const drizzleCmd = `${runnerCommand(detectPackageManager(), '').trim()} drizzle-kit generate --custom --name=${migrationName}`

  if (options.dryRun) {
    p.log.info('Dry run — no changes will be made.')
    const source = options.latest
      ? 'Would download EQL install SQL from GitHub'
      : 'Would use bundled EQL install SQL'
    p.note(
      `Would run: ${drizzleCmd}\n${source}\nWould write SQL to migration file in ${outDir}`,
      'Dry Run',
    )
    p.outro('Dry run complete.')
    return
  }

  let generatedMigrationPath: string | undefined

  // Step 1: Generate a custom Drizzle migration
  s.start('Generating custom Drizzle migration...')

  try {
    execSync(drizzleCmd, {
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
  // in one go, rather than requiring an out-of-band `stash eql install`.
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
    `Run your Drizzle migrations to install EQL:\n\n  ${runnerCommand(detectPackageManager(), '').trim()} drizzle-kit migrate`,
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
/**
 * Route the install between the drizzle / supabase-migration / direct paths
 * for the requested EQL generation. Pure — no I/O, no prompts — so the v3
 * fallback behaviour is unit-testable.
 *
 * v3 supports the direct path only: auto-detected drizzle falls back to
 * direct with a user-facing notice (explicit `--drizzle`/`--migration` are
 * already rejected by {@link validateInstallFlags}), and the Supabase
 * migration-vs-direct mode selection is skipped entirely.
 */
export function routeInstallPathForEqlVersion(
  eqlVersion: 2 | 3,
  resolved: { supabase: boolean; drizzle: boolean },
): {
  drizzle: boolean
  useSupabaseInstallModeSelection: boolean
  notice?: string
} {
  if (eqlVersion === 3) {
    return {
      drizzle: false,
      useSupabaseInstallModeSelection: false,
      notice: resolved.drizzle
        ? 'EQL v3 does not support the Drizzle migration path yet — installing directly.'
        : undefined,
    }
  }
  return {
    drizzle: resolved.drizzle,
    useSupabaseInstallModeSelection: resolved.supabase,
  }
}

/**
 * `stash eql install` is the wrong tool in a Prisma Next project: Prisma Next
 * contributes a `migrations/cipherstash/` control space that installs the EQL
 * bundle as part of `prisma-next migration apply`, in the same ledger as the
 * app schema. Running the standalone installer applies EQL out-of-band from
 * that ledger. `stash init --prisma-next` already skips the installer; this
 * guards the manual-invocation path too.
 *
 * Returns the guidance string when the install should be blocked, else null.
 * `--force` overrides (an escape hatch for a deliberate standalone install).
 * Pure + cwd-injected so it unit-tests without a real project.
 */
export function prismaNextInstallGuard(
  cwd: string,
  options: Pick<InstallOptions, 'force'>,
): string | null {
  if (options.force) return null
  if (!detectPrismaNext(cwd)) return null
  return (
    `${messages.eql.prismaNextDetected} (found prisma-next.config.* or @cipherstash/prisma-next). ` +
    'Prisma Next installs the EQL bundle through its own migration system — run ' +
    '`prisma-next migration apply` instead of `stash eql install`. ' +
    'Pass --force to run the standalone installer against this database anyway.'
  )
}

export function validateInstallFlags(options: InstallOptions): string | null {
  if (options.migration && options.direct) {
    return '`--migration` and `--direct` are mutually exclusive. Pick one.'
  }

  if (
    options.eqlVersion !== undefined &&
    options.eqlVersion !== '2' &&
    options.eqlVersion !== '3'
  ) {
    return `Unknown \`--eql-version ${options.eqlVersion}\`. Supported values: 2, 3.`
  }

  // `--migration` / `--direct` / `--migrations-dir` require `--supabase`. Check
  // this before the version gate below so a bare `--migration` still points at
  // the missing `--supabase` (its more fundamental prerequisite) rather than
  // the version.
  const subFlag =
    options.migration === true
      ? '--migration'
      : options.direct === true
        ? '--direct'
        : options.migrationsDir !== undefined
          ? '--migrations-dir'
          : null

  if (subFlag !== null && options.supabase !== true) {
    return `\`${subFlag}\` requires \`--supabase\`. Re-run with \`eql install --supabase ${subFlag}\`.`
  }

  // v3 is the default and installs via the direct path only. The Drizzle /
  // Supabase-migration / `--latest` paths are v2-only, so they require an
  // explicit `--eql-version 2` — otherwise they'd silently resolve to a v3
  // direct install that ignores what the user asked for. `--migrations-dir`
  // only feeds the Supabase v2 migration-file path, so it's in the same bucket.
  const resolvedVersion = resolveEqlVersion(options.eqlVersion)
  if (resolvedVersion === 3) {
    const v2OnlyFlag = options.drizzle
      ? '--drizzle'
      : options.migration
        ? '--migration'
        : options.latest
          ? '--latest'
          : options.migrationsDir !== undefined
            ? '--migrations-dir'
            : null
    if (v2OnlyFlag) {
      return options.eqlVersion === '3'
        ? `\`--eql-version 3\` does not support \`${v2OnlyFlag}\` yet — v3 currently installs via the direct path only.`
        : `\`${v2OnlyFlag}\` requires EQL v2. Re-run with \`--eql-version 2 ${v2OnlyFlag}\` (v3 is the default and installs via the direct path only).`
    }
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
  const interactive = isInteractive()
  const decided = chooseSupabaseInstallMode(options, projectInfo, interactive)

  if (decided !== null) {
    if (
      !interactive &&
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
