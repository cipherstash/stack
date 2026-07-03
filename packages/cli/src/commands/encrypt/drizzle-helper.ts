import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { readdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { detectPackageManager, runnerArgv } from '@/commands/init/utils.js'

/**
 * Scaffold a custom Drizzle Kit migration file with a known name and write
 * the supplied SQL into it. Mirrors the dance `eql install --drizzle` already
 * does — `drizzle-kit generate --custom` creates the file and records the
 * journal entry / snapshot, then we overwrite the empty body with our SQL.
 *
 * Used by `encrypt drop` (to ship the plaintext-column drop migration in a
 * shape `drizzle-kit migrate` actually picks up) and `encrypt cutover` (to
 * record the live rename so Drizzle's snapshot reflects post-cutover
 * reality).
 *
 * Throws if `drizzle-kit` isn't on PATH or the generated file can't be
 * located afterwards. Callers should fall back to the self-named-file
 * approach for non-Drizzle projects.
 */
export async function scaffoldDrizzleMigration(opts: {
  /**
   * Migration name passed to `drizzle-kit generate --custom --name=<name>`.
   * Drizzle prefixes with the next sequential index (`0003_<name>.sql`).
   */
  name: string
  /** Drizzle's `out` directory, defaults to `./drizzle` if unset. */
  outDir: string
  /** SQL to write into the generated file. */
  sql: string
}): Promise<{ path: string }> {
  const outDir = resolve(opts.outDir)
  if (!existsSync(outDir)) {
    throw new Error(
      `Drizzle output directory not found: ${outDir}\nMake sure drizzle-kit is configured correctly (check drizzle.config.ts's \`out\`).`,
    )
  }

  // `drizzle-kit generate --custom` scaffolds an empty migration file with
  // the right prefix and records the journal/snapshot entry. spawnSync
  // (not execSync) so opts.name can't escape into the shell — names like
  // `cutover_T_C` are agent-controlled and could in principle include
  // special characters.
  const { command, prefixArgs } = runnerArgv(detectPackageManager())
  const cp = spawnSync(
    command,
    [
      ...prefixArgs,
      'drizzle-kit',
      'generate',
      '--custom',
      `--name=${opts.name}`,
    ],
    { stdio: 'pipe', encoding: 'utf-8' },
  )
  if (cp.error || cp.status !== 0) {
    const stderr = typeof cp.stderr === 'string' ? cp.stderr.trim() : undefined
    throw new Error(
      `Failed to scaffold Drizzle migration: ${stderr ?? cp.error?.message ?? 'unknown error'}`,
    )
  }

  const generatedPath = await findLatestNamedMigration(outDir, opts.name)
  await writeFile(generatedPath, opts.sql, 'utf-8')

  return { path: generatedPath }
}

/**
 * Find the most recent `0NNN_<name>.sql` in the Drizzle out directory.
 * Drizzle's flat numbered prefix means string-sort is the right order.
 */
async function findLatestNamedMigration(
  outDir: string,
  name: string,
): Promise<string> {
  const entries = await readdir(outDir)
  const matching = entries
    .filter((entry) => entry.endsWith('.sql') && entry.includes(name))
    .sort()
  if (matching.length === 0) {
    throw new Error(
      `Could not find a migration matching "${name}" in ${outDir} after running drizzle-kit generate.`,
    )
  }
  return join(outDir, matching[matching.length - 1] as string)
}
