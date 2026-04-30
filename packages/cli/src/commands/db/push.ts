import { loadEncryptConfig, loadStashConfig } from '@/config/index.js'
import type { EncryptConfig } from '@cipherstash/stack/schema'
import { toEqlCastAs } from '@cipherstash/stack/schema'
import type { CastAs } from '@cipherstash/stack/schema'
import * as p from '@clack/prompts'
import pg from 'pg'
import { validateEncryptConfig } from './validate.js'

/**
 * Transform an EncryptConfig so that all `cast_as` values use EQL-compatible
 * types (e.g. `'number'` → `'double'`, `'string'` → `'text'`, `'json'` → `'jsonb'`).
 */
function toEqlConfig(config: EncryptConfig): Record<string, unknown> {
  const tables: Record<string, Record<string, unknown>> = {}

  for (const [tableName, columns] of Object.entries(config.tables)) {
    const eqlColumns: Record<string, unknown> = {}
    for (const [columnName, column] of Object.entries(columns)) {
      eqlColumns[columnName] = {
        ...column,
        cast_as: toEqlCastAs(column.cast_as as CastAs),
      }
    }
    tables[tableName] = eqlColumns
  }

  return { v: config.v, tables }
}

export async function pushCommand(options: {
  dryRun?: boolean
  databaseUrl?: string
}) {
  p.intro('npx @cipherstash/cli db push')
  p.log.info(
    'This command pushes the encryption schema to the database for use with CipherStash Proxy.\nIf you are using the SDK directly (Drizzle, Supabase, or plain PostgreSQL), this step is not required.',
  )

  await resolveDatabaseUrl({ databaseUrlFlag: options.databaseUrl })

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig()
  s.stop('Configuration loaded.')

  s.start(`Loading encrypt client from ${config.client}...`)
  const encryptConfig = await loadEncryptConfig(config.client)
  s.stop('Encrypt client loaded and validated.')

  // Run validation as a pre-push check (warn but don't block)
  if (encryptConfig) {
    const issues = validateEncryptConfig(encryptConfig, {})
    if (issues.length > 0) {
      p.log.warn('Schema validation found issues:')
      for (const issue of issues) {
        const logFn =
          issue.severity === 'error'
            ? p.log.error
            : issue.severity === 'warning'
              ? p.log.warn
              : p.log.info
        logFn(`${issue.table}.${issue.column}: ${issue.message}`)
      }
      console.log()
    }
  }

  // Transform SDK types to EQL types for the database
  const eqlConfig = toEqlConfig(encryptConfig)

  if (options.dryRun) {
    p.log.info('Dry run — no changes will be pushed.')
    p.note(JSON.stringify(eqlConfig, null, 2), 'Encryption Schema')
    p.outro('Dry run complete.')
    return
  }

  const client = new pg.Client({ connectionString: config.databaseUrl })

  try {
    s.start('Connecting to Postgres...')
    await client.connect()
    s.stop('Connected to Postgres.')

    s.start('Updating eql_v2_configuration...')
    await client.query(`
      UPDATE eql_v2_configuration SET state = 'inactive'
    `)

    await client.query(
      `
        INSERT INTO eql_v2_configuration (state, data) VALUES ('active', $1)
      `,
      [eqlConfig],
    )
    s.stop('Updated eql_v2_configuration.')

    p.outro('Push complete.')
  } catch (error) {
    s.stop('Failed.')
    p.log.error(
      error instanceof Error ? error.message : 'Failed to push configuration.',
    )
    process.exit(1)
  } finally {
    await client.end()
  }
}
