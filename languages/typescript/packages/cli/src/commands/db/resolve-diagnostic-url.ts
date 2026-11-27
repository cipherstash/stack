import { resolveDatabaseUrl } from '@/config/database-url.js'
import { findConfigFile, loadStashConfig } from '@/config/index.js'

/**
 * The database-URL resolution shared by the read-only diagnostic commands
 * (`eql preflight`, `eql verify`). Both run BEFORE anything is set up, so a
 * missing stash.config.ts must not fail them — fall back to the plain
 * DATABASE_URL resolution chain the installer itself uses when no config
 * exists yet. In `json` mode the resolver keeps stdout parseable:
 * informational chrome and the interactive prompt are suppressed (`quiet`)
 * and failures come out as the shared `{ status: 'error', code, message }`
 * envelope (`jsonErrors`).
 *
 * An explicit `--database-url` always wins. It bypasses config loading
 * entirely, as it does for `stash eql install --database-url …`, so the
 * database the user named is the database that gets judged. A hand-set
 * literal `databaseUrl` in a stash.config.ts found up the directory tree must
 * not redirect a diagnostic to a different database: preflight would then
 * report the capabilities of a database the user did not name, and the user
 * would choose column types from that answer (#1966).
 *
 * With no flag, the order is: the config's `databaseUrl` if a stash.config.ts
 * is found, else the DATABASE_URL resolution chain.
 */
export async function resolveDiagnosticDatabaseUrl(options: {
  databaseUrlFlag: string | undefined
  json: boolean
}): Promise<string> {
  const { databaseUrlFlag, json } = options
  if (databaseUrlFlag !== undefined) {
    return resolveDatabaseUrl({
      databaseUrlFlag,
      quiet: json,
      jsonErrors: json,
    })
  }
  const configPath = findConfigFile(process.cwd())
  if (configPath) {
    const config = await loadStashConfig(
      { quiet: json, jsonErrors: json },
      configPath,
    )
    return config.databaseUrl
  }
  return resolveDatabaseUrl({ quiet: json, jsonErrors: json })
}
