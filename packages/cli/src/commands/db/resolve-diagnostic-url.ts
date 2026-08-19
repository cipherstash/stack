import * as p from '@clack/prompts'
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
 * The two commands differ on one deliberate point, `flagWins`:
 *
 * - `false` (preflight): mirrors `installCommand`'s config-loading path — a
 *   hand-set literal `databaseUrl` in stash.config.ts beats `--database-url`.
 *   Surprising enough to say out loud, to stderr in json mode.
 * - `true` (verify): mirrors `installCommand`'s one-shot path — an explicit
 *   `--database-url` bypasses config loading entirely, so the database the
 *   user named is the database that gets judged. Verify pairs with one-shot
 *   installs (`stash eql install --database-url …`), and a config literal
 *   found up the directory tree silently redirecting the verdict to a
 *   different database would defeat the flag's whole purpose.
 */
export async function resolveDiagnosticDatabaseUrl(options: {
  databaseUrlFlag: string | undefined
  json: boolean
  flagWins: boolean
  /** Present-participle for the config-precedence warning, e.g. `Probing`. */
  verb: string
}): Promise<string> {
  const { databaseUrlFlag, json, flagWins, verb } = options
  if (flagWins && databaseUrlFlag !== undefined) {
    return resolveDatabaseUrl({
      databaseUrlFlag,
      quiet: json,
      jsonErrors: json,
    })
  }
  const configPath = findConfigFile(process.cwd())
  if (configPath) {
    const config = await loadStashConfig(
      { databaseUrlFlag, quiet: json, jsonErrors: json },
      configPath,
    )
    if (
      databaseUrlFlag !== undefined &&
      config.databaseUrl !== databaseUrlFlag.trim()
    ) {
      const warning = `Ignoring --database-url: ${configPath} sets an explicit databaseUrl that takes precedence. ${verb} the config's database.`
      if (json) {
        process.stderr.write(`${warning}\n`)
      } else {
        p.log.warn(warning)
      }
    }
    return config.databaseUrl
  }
  return resolveDatabaseUrl({ databaseUrlFlag, quiet: json, jsonErrors: json })
}
