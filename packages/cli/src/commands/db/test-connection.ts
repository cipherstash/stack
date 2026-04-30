import { resolveDatabaseUrl } from '@/config/database-url.js'
import { loadStashConfig } from '@/config/index.js'
import * as p from '@clack/prompts'
import pg from 'pg'

export async function testConnectionCommand(
  options: { databaseUrl?: string } = {},
) {
  p.intro('npx @cipherstash/cli db test-connection')

  await resolveDatabaseUrl({ databaseUrlFlag: options.databaseUrl })

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig()
  s.stop('Configuration loaded.')

  const client = new pg.Client({ connectionString: config.databaseUrl })

  try {
    s.start('Connecting to database...')
    await client.connect()
    s.stop('Connected successfully.')

    const [versionResult, userResult, dbResult] = await Promise.all([
      client.query<{ version: string }>('SELECT version()'),
      client.query<{ current_user: string }>('SELECT current_user'),
      client.query<{ current_database: string }>('SELECT current_database()'),
    ])

    const serverVersion = versionResult.rows[0]?.version ?? 'unknown'
    const currentUser = userResult.rows[0]?.current_user ?? 'unknown'
    const currentDatabase = dbResult.rows[0]?.current_database ?? 'unknown'

    // Extract the short version string (e.g. "PostgreSQL 16.2") from the full version output
    const shortVersion = serverVersion.split(' on ')[0] ?? serverVersion

    console.log()
    p.log.info(`Database: ${currentDatabase}`)
    p.log.info(`User:     ${currentUser}`)
    p.log.info(`Server:   ${shortVersion}`)

    p.outro('Done!')
  } catch (error) {
    s.stop('Failed.')

    const message =
      error instanceof Error ? error.message : 'An unknown error occurred'

    p.log.error(`Failed to connect to database: ${message}`)
    console.log()
    p.log.info('Check your databaseUrl in stash.config.ts or .env file.')
    process.exit(1)
  } finally {
    await client.end()
  }
}
