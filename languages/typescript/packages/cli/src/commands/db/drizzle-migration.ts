import { existsSync } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { isAbsolute, join, resolve } from 'node:path'

/**
 * Helpers for locating the file `drizzle-kit generate --custom` just wrote.
 * Shared by `eql migration --drizzle` and the `encrypt drop` / `decrypt`
 * scaffolds, so both agree on where drizzle-kit's `drizzle.config.ts` sent it.
 */

/**
 * Find the most recently generated Drizzle migration matching the name.
 *
 * Matches the exact `_<name>.sql` suffix, so a longer name that merely contains
 * the stem (`drop_users_email_backup`) is never mistaken for it.
 */
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

// biome-ignore lint/suspicious/noControlCharactersInRegex: matching ESC is the point
const ANSI_ESCAPE = /\u001b\[[0-9;]*[A-Za-z]/g

function stripAnsi(text: string): string {
  return text.replace(ANSI_ESCAPE, '')
}

/**
 * Pull the migration path out of drizzle-kit's own success line:
 *
 *     [✓] Your SQL migration file ➜ drizzle/0000_install-eql.sql 🚀
 *
 * Since we no longer pass `--out` (drizzle-kit rejects the run when we do —
 * see `generateDrizzleEqlMigration`), `drizzle.config.ts` owns the output
 * directory and this line is how we learn it. The path is printed relative to
 * the cwd drizzle-kit ran in, which is ours.
 *
 * Returns `undefined` unless the file is actually there, so an unrecognised
 * banner or a moved file falls through to the directory scan rather than
 * pointing the SQL write at a path that does not exist.
 */
export function parseReportedMigrationPath(
  stdout: string | undefined,
): string | undefined {
  if (!stdout) return undefined
  // Scanned per line, taking everything between the arrow and the LAST `.sql`
  // on it, because an output directory may contain spaces — a `\S+` pattern
  // truncates such a path, fails the existence check, and drops us into the
  // fallback scan of an unrelated directory.
  //
  // Last line wins: one invocation writes one file, but a wrapper that echoes
  // its own banner first should not shadow drizzle-kit's.
  let found: string | undefined
  for (const line of stdout.split(/\r?\n/)) {
    const arrow = line.indexOf('➜')
    if (arrow === -1) continue
    // drizzle-kit colours its banner on a TTY-like stdout; escape codes inside
    // the path would fail the existence check and drop us into the fallback.
    const rest = stripAnsi(line.slice(arrow + 1))
    const end = rest.lastIndexOf('.sql')
    if (end === -1) continue
    const candidate = rest.slice(0, end + '.sql'.length).trim()
    if (!candidate) continue
    const abs = isAbsolute(candidate) ? candidate : resolve(candidate)
    if (existsSync(abs)) found = abs
  }
  return found
}
