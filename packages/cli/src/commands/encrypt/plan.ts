import { loadStashConfig } from '@/config/index.js'
import { latestByColumn, readManifest } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'

/**
 * CLI handler for `stash encrypt plan`. Reads the repo manifest and the
 * latest `cs_migrations` state for each declared column, and prints the
 * transitions needed to reach each column's `targetPhase`.
 *
 * No state changes are made. This is the "what would happen if I
 * `advance`d everything" preview.
 */
export async function planCommand() {
  p.intro('npx @cipherstash/cli encrypt plan')

  const config = await loadStashConfig()
  const manifest = await readManifest(process.cwd())

  if (!manifest) {
    p.log.warn('No .cipherstash/migrations.json found.')
    p.outro('Nothing to plan.')
    return
  }

  const client = new pg.Client({ connectionString: config.databaseUrl })
  try {
    await client.connect()
    const state = await latestByColumn(client)

    const actions: string[] = []
    for (const [tableName, columns] of Object.entries(manifest.tables)) {
      for (const column of columns) {
        const key = `${tableName}.${column.column}`
        const current = state.get(key)
        if (!current) {
          actions.push(
            `  + ${key}: no migration recorded; start with \`stash encrypt advance --to schema-added\``,
          )
          continue
        }
        if (current.phase !== column.targetPhase) {
          actions.push(`  → ${key}: ${current.phase} → ${column.targetPhase}`)
        } else {
          actions.push(`  ✓ ${key}: already at ${column.targetPhase}`)
        }
      }
    }

    p.note(actions.join('\n') || '(no changes)', 'Plan')
    p.outro('Done.')
  } catch (error) {
    p.log.error(error instanceof Error ? error.message : 'Plan failed.')
    process.exit(1)
  } finally {
    await client.end()
  }
}
