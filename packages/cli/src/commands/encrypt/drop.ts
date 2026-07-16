import fs from 'node:fs'
import path from 'node:path'
import {
  appendEvent,
  countUnencrypted,
  progress,
  setManifestTargetPhase,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { detectDrizzle } from '@/commands/db/detect.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { scaffoldDrizzleMigration } from './drizzle-helper.js'
import { resolveColumnLifecycle } from './lib/resolve-eql.js'

/**
 * Options accepted by `stash encrypt drop`. Generates a migration file
 * that drops the now-unused plaintext column (renamed to `<col>_plaintext`
 * by cutover). Does *not* apply the migration — the user runs their usual
 * migration tool (drizzle-kit, prisma, psql) to actually execute it.
 */
export interface DropCommandOptions {
  /** Physical table name, e.g. `users`. */
  table: string
  /**
   * Physical column — the original plaintext name. The generated migration
   * drops `<column>_plaintext` (the name the column has *after* cutover).
   */
  column: string
  /**
   * Directory to write the generated `.sql` migration into, relative to
   * the current working directory. Default: `./drizzle`. Use `./migrations`
   * (or similar) for Prisma / manual psql workflows.
   */
  migrationsDir?: string
}

/**
 * CLI handler for `stash encrypt drop`. Requires the column to be in
 * phase `cut-over`; otherwise errors out.
 *
 * For Drizzle projects, scaffolds the migration via `drizzle-kit generate
 * --custom` so the file lands with the correct sequential prefix and a
 * journal/snapshot entry — which is what `drizzle-kit migrate` actually
 * picks up. Hand-rolling the file (the prior behaviour) wrote a
 * timestamped `<ts>_drop_*.sql` that Drizzle ignored.
 *
 * For non-Drizzle projects, falls back to the self-named file behaviour
 * — a clearly named SQL file the user reviews and applies with their own
 * tooling (Prisma migrate, psql, etc.).
 */
export async function dropCommand(options: DropCommandOptions) {
  p.intro(runnerCommand(detectPackageManager(), 'stash encrypt drop'))

  const config = await loadStashConfig()
  const client = new pg.Client({ connectionString: config.databaseUrl })
  let exitCode = 0

  try {
    await client.connect()

    // The plaintext column's name depends on the EQL version's lifecycle:
    // v2's cut-over renames `<col>` → `<col>_plaintext` (so that's what we
    // drop, after `cut-over`); v3 has no rename — the app switched to the
    // encrypted column by name, so the original `<col>` IS the plaintext
    // column, droppable straight after `backfilled`. The version and the
    // encrypted column's name are resolved from the DOMAIN TYPES (manifest
    // name as a hint) — the `<col>_encrypted` naming is a convention only.
    const { info } = await resolveColumnLifecycle(
      client,
      options.table,
      options.column,
    )
    const isV3 = info?.version === 3
    const encryptedColumn = info?.column ?? `${options.column}_encrypted`
    const requiredPhase = isV3 ? 'backfilled' : 'cut-over'
    const plaintextToDrop = isV3
      ? options.column
      : `${options.column}_plaintext`

    const state = await progress(client, options.table, options.column)
    if (state?.phase !== requiredPhase) {
      p.log.error(
        `Cannot generate drop migration: ${options.table}.${options.column} is in phase '${state?.phase ?? '—'}'. Must be '${requiredPhase}'${isV3 ? ' (EQL v3 has no cut-over — backfill, switch the app to the encrypted column, then drop)' : ''}.`,
      )
      exitCode = 1
      return
    }

    if (isV3) {
      // The phase gate above proves a backfill FINISHED at some point; it
      // says nothing about rows written since (a bulk import or a service
      // that isn't dual-writing leaves plaintext-only rows). Dropping the
      // original column is the one irreversible step in the v3 ladder, so
      // verify live coverage before generating the migration.
      const unencrypted = await countUnencrypted(
        client,
        options.table,
        options.column,
        encryptedColumn,
      )
      if (unencrypted > 0) {
        p.log.error(
          `Refusing to generate the drop migration: ${unencrypted} row(s) in ${options.table} have "${options.column}" set but "${encryptedColumn}" NULL — dropping "${options.column}" would permanently destroy that data. Likely rows written without dual-writes since the backfill. Re-run:\n  stash encrypt backfill --table ${options.table} --column ${options.column}\nthen generate the drop again.`,
        )
        exitCode = 1
        return
      }
      p.log.success(
        `Verified: no rows with "${options.column}" set and "${encryptedColumn}" NULL.`,
      )
      p.log.info(
        `${options.table}.${encryptedColumn} is EQL v3 (${info?.domain}) — the drop targets the original plaintext column "${options.column}" (v3 has no rename, so there is no "${options.column}_plaintext"). Make sure your application reads/writes ${encryptedColumn} before applying this migration.`,
      )
    }

    const dot = options.table.indexOf('.')
    const qualifiedTable =
      dot >= 0
        ? `"${options.table.slice(0, dot)}"."${options.table.slice(dot + 1)}"`
        : `"${options.table}"`
    const dropSql = `-- Generated by stash encrypt drop\n-- Drops the plaintext column now that ${options.table}.${isV3 ? encryptedColumn : options.column} is encrypted.\n\nALTER TABLE ${qualifiedTable} DROP COLUMN "${plaintextToDrop}";\n`

    const cwd = process.cwd()
    const migrationsDir = options.migrationsDir ?? 'drizzle'
    const isDrizzle = detectDrizzle(cwd)
    let filePath: string
    let nextStep: string

    if (isDrizzle) {
      // Scaffold via drizzle-kit so the migration is journaled + snapshotted.
      // Without this, the file ships but `drizzle-kit migrate` never picks it
      // up because the journal doesn't reference it.
      const result = await scaffoldDrizzleMigration({
        name: `drop_${options.table}_${plaintextToDrop}`,
        outDir: migrationsDir,
        sql: dropSql,
      })
      filePath = result.path
      nextStep = `Apply with your usual Drizzle migrate command:\n  ${runnerCommand(detectPackageManager(), 'drizzle-kit migrate')}`
    } else {
      // Non-Drizzle fallback: emit a timestamped SQL file the user
      // applies with whichever migration tool they're running.
      const dirAbs = path.resolve(cwd, migrationsDir)
      fs.mkdirSync(dirAbs, { recursive: true })
      const ts = new Date()
        .toISOString()
        .replace(/[-:.TZ]/g, '')
        .slice(0, 14)
      const fileName = `${ts}_drop_${options.table}_${plaintextToDrop}.sql`
      filePath = path.join(dirAbs, fileName)
      fs.writeFileSync(filePath, dropSql, 'utf-8')
      nextStep = `Review the migration, then apply with your migration tool:\n  - prisma migrate deploy\n  - psql -f ${fileName}`
    }

    await appendEvent(client, {
      tableName: options.table,
      columnName: options.column,
      event: 'dropped',
      phase: 'dropped',
      details: { migrationFile: filePath, drizzleScaffolded: isDrizzle },
    })

    // Bump the manifest's target phase so `encrypt plan` reflects the
    // user's commitment to fully removing the plaintext column. No-op
    // when the column wasn't tracked in the manifest yet.
    await setManifestTargetPhase(options.table, options.column, 'dropped')

    p.log.success(`Migration written to ${filePath}`)
    p.note(nextStep, 'Next')
    p.outro('Drop migration generated.')
  } catch (error) {
    p.log.error(
      error instanceof Error ? error.message : 'Drop generation failed.',
    )
    exitCode = 1
  } finally {
    await client.end()
    // In `finally` (not after the try/catch) deliberately: the precondition
    // guards above `return` from inside `try`, which skips any code placed
    // after the block — so a trailing `if (exitCode) process.exit(...)`
    // was unreachable on exactly the failure paths it existed for, and
    // guard failures exited 0.
    if (exitCode) process.exit(exitCode)
  }
}
