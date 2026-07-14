import { existsSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import {
  loadBundledEqlSql,
  SUPABASE_PERMISSIONS_SQL,
} from '@/installer/index.js'

/**
 * Filename of the Supabase migration that installs CipherStash EQL.
 *
 * Supabase orders migrations lexically by the `YYYYMMDDHHMMSS_` prefix; an
 * all-zero prefix is guaranteed to sort before any real timestamp, so this
 * file always runs first on `supabase db reset` and `supabase migration up`.
 * That ordering is the whole point of this code path — without it, user
 * migrations referencing `eql_v2_encrypted` blow up because the EQL types
 * aren't installed yet.
 */
export const SUPABASE_EQL_MIGRATION_FILENAME =
  '00000000000000_cipherstash_eql.sql'

/**
 * Header comment block prepended to the generated migration. Explains *why*
 * this file exists for future maintainers reading their own migrations
 * directory. The runner is resolved at call time based on the detected
 * package manager.
 */
function migrationHeader(runner: string): string {
  return `-- CipherStash EQL — installed by \`${runner} stash eql install --supabase --migration\`.
--
-- This migration installs the CipherStash Encrypt Query Language (EQL) types,
-- functions, and operators into the \`eql_v2\` schema, then grants Supabase's
-- \`anon\`, \`authenticated\`, and \`service_role\` roles the access they need.
--
-- The all-zero \`YYYYMMDDHHMMSS\` prefix is intentional: Supabase orders
-- migrations lexically, so this file runs before any user migration that
-- references the \`eql_v2_encrypted\` type. Do not rename it.
--
-- To upgrade EQL, re-run the install command — it will refuse to overwrite
-- this file unless you pass --force.
--
-- Docs: https://cipherstash.com/docs/stack/cipherstash/supabase
`
}

export interface WriteSupabaseEqlMigrationOptions {
  /**
   * Absolute path to the directory the migration file should be written into.
   * Created (recursively) if it doesn't already exist.
   */
  migrationsDir: string
  /**
   * Overwrite an existing migration file at this path. When `false` (default)
   * an existing file causes the function to throw.
   */
  force?: boolean
  /**
   * Whether to use the no-operator-family EQL bundle. Supabase always wants
   * this — we expose the flag for symmetry with the runtime install path and
   * to leave room for future provider variants.
   */
  excludeOperatorFamily?: boolean
}

export interface WriteSupabaseEqlMigrationResult {
  /** Absolute path to the migration file that was written. */
  path: string
  /** Whether an existing file at `path` was overwritten. */
  overwritten: boolean
}

/**
 * Generate the `<migrationsDir>/00000000000000_cipherstash_eql.sql` migration.
 *
 * The file body is, in order:
 *   1. Migration header (generated from {@link migrationHeader}) — explains why the file exists.
 *   2. The bundled `cipherstash-encrypt-supabase.sql` install script.
 *   3. {@link SUPABASE_PERMISSIONS_SQL} — the same grants the runtime install
 *      path issues. One source of truth for both code paths.
 *
 * @throws if the target file already exists and `force` is `false`.
 */
export async function writeSupabaseEqlMigration(
  options: WriteSupabaseEqlMigrationOptions,
): Promise<WriteSupabaseEqlMigrationResult> {
  const {
    migrationsDir,
    force = false,
    excludeOperatorFamily = false,
  } = options

  const targetPath = join(migrationsDir, SUPABASE_EQL_MIGRATION_FILENAME)
  const alreadyExists = existsSync(targetPath)

  if (alreadyExists && !force) {
    throw new Error(
      `Refusing to overwrite ${targetPath}: file already exists. Re-run with --force to overwrite.`,
    )
  }

  // The Supabase migration-file flow is v2-only (v3 has no migration-file
  // path), so pin `eqlVersion: 2` explicitly — otherwise it would follow the
  // v3 default and emit `cipherstash-encrypt-v3-supabase.sql` alongside the v2
  // `SUPABASE_PERMISSIONS_SQL` below, producing a mismatched migration. We also
  // pass both supabase/no-operator-family flags so intent is explicit and
  // `loadBundledEqlSql` resolves the supabase file even if selection rules ever
  // change.
  const eqlSql = loadBundledEqlSql({
    eqlVersion: 2,
    supabase: true,
    excludeOperatorFamily: excludeOperatorFamily || true,
  })

  const pm = detectPackageManager()
  const runner = runnerCommand(pm, '').trim()
  const header = migrationHeader(runner)

  const body = [
    header,
    '',
    eqlSql.trimEnd(),
    '',
    '-- Grant access to Supabase roles (anon, authenticated, service_role).',
    SUPABASE_PERMISSIONS_SQL.trimEnd(),
    '',
  ].join('\n')

  await mkdir(migrationsDir, { recursive: true })
  await writeFile(targetPath, body, 'utf-8')

  return { path: targetPath, overwritten: alreadyExists }
}
