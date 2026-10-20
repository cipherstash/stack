import fs from 'node:fs'
import path from 'node:path'
import { detectDrizzle } from '@/commands/db/detect.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { scaffoldDrizzleMigration } from '../drizzle-helper.js'

/** Where a generated migration landed, and how to apply it. */
export interface WrittenMigration {
  filePath: string
  /** Ready-to-print "how to apply this" guidance for the detected tooling. */
  nextStep: string
  /** True when the file was scaffolded (journaled) through drizzle-kit. */
  drizzleScaffolded: boolean
}

/**
 * Write a generated SQL migration the way the user's tooling will pick it up.
 * Shared by `stash encrypt drop` and the `stash decrypt` commands, so both
 * lifecycle directions land migrations identically.
 *
 * For Drizzle projects, scaffolds the file via `drizzle-kit generate --custom`
 * so it gets the correct sequential prefix and a journal/snapshot entry —
 * which is what `drizzle-kit migrate` actually picks up. A hand-named file
 * would ship but never run.
 *
 * Otherwise, writes a timestamped `<ts>_<stem>.sql` into `migrationsDir` for
 * the user to review and apply with their own tool (Prisma migrate, psql, …).
 */
export async function writeMigrationFile(opts: {
  stem: string
  sql: string
  /** Relative to cwd. Default `./drizzle`. */
  migrationsDir?: string
}): Promise<WrittenMigration> {
  const cwd = process.cwd()
  const migrationsDir = opts.migrationsDir ?? 'drizzle'

  if (detectDrizzle(cwd)) {
    const result = await scaffoldDrizzleMigration({
      name: opts.stem,
      outDir: migrationsDir,
      sql: opts.sql,
    })
    return {
      filePath: result.path,
      nextStep: `Apply with your usual Drizzle migrate command:\n  ${runnerCommand(detectPackageManager(), 'drizzle-kit migrate')}`,
      drizzleScaffolded: true,
    }
  }

  const dirAbs = path.resolve(cwd, migrationsDir)
  fs.mkdirSync(dirAbs, { recursive: true })
  const ts = new Date()
    .toISOString()
    .replace(/[-:.TZ]/g, '')
    .slice(0, 14)
  const fileName = `${ts}_${opts.stem}.sql`
  const filePath = path.join(dirAbs, fileName)
  fs.writeFileSync(filePath, opts.sql, 'utf-8')
  return {
    filePath,
    nextStep: `Review the migration, then apply with your migration tool:\n  - prisma migrate deploy\n  - psql -f ${fileName}`,
    drizzleScaffolded: false,
  }
}

/**
 * Filesystem- and drizzle-kit-safe migration name derived from untrusted
 * identifiers, e.g. `buildMigrationStem('drop', 'users', 'email')` →
 * `drop_users_email`.
 */
export function buildMigrationStem(
  prefix: string,
  ...identifiers: string[]
): string {
  const sanitized = identifiers
    .map((identifier) =>
      identifier.replace(/[^A-Za-z0-9_-]+/g, '_').replace(/^_+|_+$/g, ''),
    )
    .filter(Boolean)
    .join('_')
  return `${prefix}_${sanitized || 'column'}`
}

/** Escape a string for inclusion inside a single-quoted SQL literal. */
export function sqlLiteral(value: string): string {
  return value.replace(/'/g, "''")
}
