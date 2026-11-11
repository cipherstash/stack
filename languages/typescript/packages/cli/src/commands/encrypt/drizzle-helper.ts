import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'
import {
  findGeneratedMigration,
  parseReportedMigrationPath,
} from '@/commands/db/drizzle-migration.js'
import { detectPackageManager, runnerArgv } from '@/commands/init/utils.js'

/**
 * Scaffold a custom Drizzle Kit migration file with a known name and write
 * the supplied SQL into it. Mirrors the dance `eql install --drizzle` already
 * does — `drizzle-kit generate --custom` creates the file and records the
 * journal entry / snapshot, then we overwrite the empty body with our SQL.
 *
 * Used by `encrypt drop` and the `decrypt` commands to ship the
 * plaintext-column drop migration in a shape `drizzle-kit migrate` actually
 * picks up.
 *
 * `drizzle.config.ts`'s `out` decides where drizzle-kit writes (we cannot pass
 * `--out`: it switches drizzle-kit into CLI mode — see
 * `generateDrizzleEqlMigration`), so the path drizzle-kit REPORTS is the
 * authority on where the file landed. `outDir` is only the fallback place to
 * look when that report is missing, and the fallback only accepts a file that
 * did not exist before the run — otherwise an older same-stem migration in an
 * unrelated directory would be overwritten.
 *
 * Throws if `drizzle-kit` can't run or the generated file can't be located
 * afterwards. Callers should fall back to the self-named-file approach for
 * non-Drizzle projects.
 */
export async function scaffoldDrizzleMigration(opts: {
  /**
   * Migration name passed to `drizzle-kit generate --custom --name=<name>`.
   * Drizzle prefixes with the next sequential index (`0003_<name>.sql`).
   */
  name: string
  /** Fallback directory to scan if drizzle-kit's reported path is unusable. */
  outDir: string
  /** SQL to write into the generated file. */
  sql: string
}): Promise<{ path: string; dir: string; requestedDir: string }> {
  const outDir = resolve(opts.outDir)
  const before = await listSqlFiles(outDir)

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
    const output = [cp.stdout, cp.stderr]
      .map((stream) => (typeof stream === 'string' ? stream.trim() : ''))
      .filter(Boolean)
      .join('\n')
    throw new Error(
      `Failed to scaffold Drizzle migration: ${output || cp.error?.message || 'unknown error'}`,
    )
  }

  const generatedPath =
    parseReportedMigrationPath(cp.stdout) ??
    (await findNewMigration(outDir, opts.name, before))
  // `generate --custom` leaves a comment-only placeholder (drizzle-kit writes
  // `-- Custom SQL migration file, put your code below! --`). Anything with
  // real SQL is an existing migration (a banner line naming one, a wrapper's
  // echo): never overwrite it.
  if (!isScaffoldOnly(await readFile(generatedPath, 'utf-8'))) {
    throw new Error(
      `${generatedPath} is not a drizzle-kit scaffold; refusing to overwrite it. If drizzle-kit just journaled a placeholder "${opts.name}" migration, it is in the \`out\` of your drizzle.config.ts.`,
    )
  }
  await writeFile(generatedPath, opts.sql, 'utf-8')

  return {
    path: generatedPath,
    dir: dirname(generatedPath),
    requestedDir: outDir,
  }
}

/** Blank, or nothing but `--` comment lines: no statement to lose. */
function isScaffoldOnly(content: string): boolean {
  return content
    .split(/\r?\n/)
    .every((line) => line.trim() === '' || line.trim().startsWith('--'))
}

async function listSqlFiles(dir: string): Promise<Set<string>> {
  if (!existsSync(dir)) return new Set()
  return new Set((await readdir(dir)).filter((f) => f.endsWith('.sql')))
}

/**
 * Fallback when drizzle-kit's banner is not recognised: the newest exact
 * `_<name>.sql` in `outDir`, provided this run created it. A file that was
 * already there is somebody's earlier (maybe applied) migration, and
 * overwriting it would silently lose the new one.
 */
async function findNewMigration(
  outDir: string,
  name: string,
  before: Set<string>,
): Promise<string> {
  const found = await findGeneratedMigration(outDir, name).catch(() => {
    throw new Error(
      `Could not locate the migration drizzle-kit generated for "${name}". It was not reported on stdout and is not in ${outDir}. Check the \`out\` in your drizzle.config.ts — a custom migration may have been journaled there with an empty body.`,
    )
  })
  if (before.has(basename(found))) {
    throw new Error(
      `drizzle-kit did not report where it wrote "${name}", and ${outDir} only holds a pre-existing file with that name (${found}). Refusing to overwrite it. Check the \`out\` in your drizzle.config.ts — an empty custom migration may have been journaled there.`,
    )
  }
  return found
}
