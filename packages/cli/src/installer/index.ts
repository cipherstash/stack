import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import pg from 'pg'

// EQL release, pinned to match the EQL payload format this package emits.
// Bump in lockstep with @cipherstash/protect-ffi.
const EQL_VERSION = 'eql-2.2.1'
const EQL_INSTALL_URL =
  `https://github.com/cipherstash/encrypt-query-language/releases/download/${EQL_VERSION}/cipherstash-encrypt.sql`
const EQL_INSTALL_NO_OPERATOR_FAMILY_URL =
  `https://github.com/cipherstash/encrypt-query-language/releases/download/${EQL_VERSION}/cipherstash-encrypt-supabase.sql`
const EQL_SCHEMA_NAME = 'eql_v2'

/**
 * SQL block that grants the EQL schema, tables, routines, and sequences to
 * Supabase's built-in roles (`anon`, `authenticated`, `service_role`).
 *
 * Supabase uses dedicated roles that don't own the schema, so explicit grants
 * are required. We expose this as a single multi-statement string so it can be
 * executed in one `client.query()` (Postgres accepts multi-statement strings)
 * AND embedded directly into a Supabase migration file. One source of truth
 * for both the runtime install path and the generated migration file.
 */
export const SUPABASE_PERMISSIONS_SQL = `GRANT USAGE ON SCHEMA ${EQL_SCHEMA_NAME} TO anon, authenticated, service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA ${EQL_SCHEMA_NAME} TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL ROUTINES IN SCHEMA ${EQL_SCHEMA_NAME} TO anon, authenticated, service_role;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${EQL_SCHEMA_NAME} TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${EQL_SCHEMA_NAME} GRANT SELECT ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${EQL_SCHEMA_NAME} GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ${EQL_SCHEMA_NAME} GRANT USAGE ON SEQUENCES TO anon, authenticated, service_role;
`

/**
 * Get the directory of the current file, supporting both ESM and CJS.
 */
function getCurrentDir(): string {
  // ESM: import.meta.url is available
  if (typeof import.meta?.url === 'string' && import.meta.url) {
    return dirname(new URL(import.meta.url).pathname)
  }
  // CJS: __dirname is available
  return __dirname
}

/**
 * Resolve the path to a bundled SQL file shipped with the package.
 *
 * tsup bundles everything flat:
 *   - Library: dist/index.js   → SQL at dist/sql/
 *   - CLI:     dist/bin/stash.js → SQL at dist/sql/
 *
 * We walk up from the current file until we find the sql/ directory.
 */
function bundledSqlPath(filename: string): string {
  const thisDir = getCurrentDir()

  // Try sql/ as a sibling first (library path: dist/ -> dist/sql/)
  const sibling = join(thisDir, 'sql', filename)
  if (existsSync(sibling)) return sibling

  // Try one level up (CLI path: dist/bin/ -> dist/sql/)
  const parent = join(thisDir, '..', 'sql', filename)
  if (existsSync(parent)) return resolve(parent)

  // Fallback: return the sibling path and let the caller handle the error
  return sibling
}

export interface PermissionCheckResult {
  ok: boolean
  missing: string[]
  /**
   * Whether the connected role is a Postgres superuser. Managed Postgres
   * providers (Supabase, Neon, RDS, etc.) do not grant superuser, which means
   * `CREATE OPERATOR FAMILY` / `CREATE OPERATOR CLASS` in the EQL install
   * script will fail. Callers use this to auto-fall back to the
   * no-operator-family install variant (OPE index only) instead of aborting.
   */
  isSuperuser: boolean
}

export class EQLInstaller {
  private readonly databaseUrl: string

  constructor(options: { databaseUrl: string }) {
    this.databaseUrl = options.databaseUrl
  }

  /**
   * Check whether the connected database role has the permissions required
   * to install EQL.
   *
   * EQL installation requires:
   * - SUPERUSER or CREATEDB — for `CREATE EXTENSION IF NOT EXISTS pgcrypto`
   * - CREATE on the current database — for `CREATE SCHEMA eql_v2`
   * - CREATE on the public schema — for `CREATE TYPE public.eql_v2_encrypted`
   */
  async checkPermissions(): Promise<PermissionCheckResult> {
    const client = new pg.Client({ connectionString: this.databaseUrl })

    try {
      await client.connect()

      const missing: string[] = []

      // Check if the role is a superuser (can do everything)
      const roleResult = await client.query(`
        SELECT
          rolsuper,
          rolcreatedb
        FROM pg_roles
        WHERE rolname = current_user
      `)

      const role = roleResult.rows[0]
      const isSuperuser = role?.rolsuper === true

      if (isSuperuser) {
        return { ok: true, missing: [], isSuperuser: true }
      }

      // Not a superuser — check individual permissions

      // CREATE on the current database (needed for CREATE SCHEMA, CREATE EXTENSION)
      const dbCreateResult = await client.query(`
        SELECT has_database_privilege(current_user, current_database(), 'CREATE') AS has_create
      `)
      if (!dbCreateResult.rows[0]?.has_create) {
        missing.push(
          'CREATE on database (required for CREATE SCHEMA and CREATE EXTENSION)',
        )
      }

      // CREATE on the public schema (needed for CREATE TYPE public.eql_v2_encrypted)
      const schemaCreateResult = await client.query(`
        SELECT has_schema_privilege(current_user, 'public', 'CREATE') AS has_create
      `)
      if (!schemaCreateResult.rows[0]?.has_create) {
        missing.push(
          'CREATE on public schema (required for CREATE TYPE public.eql_v2_encrypted)',
        )
      }

      // Check if pgcrypto is already installed — if not, we need CREATE EXTENSION privilege
      const pgcryptoResult = await client.query(`
        SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
      `)
      if (pgcryptoResult.rowCount === 0 || pgcryptoResult.rowCount === null) {
        // pgcrypto not installed — need to be able to create extensions
        // This typically requires superuser or the role must be the extension owner
        if (!role?.rolcreatedb) {
          missing.push(
            'SUPERUSER or extension owner (required for CREATE EXTENSION pgcrypto)',
          )
        }
      }

      return { ok: missing.length === 0, missing, isSuperuser: false }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /**
   * Check whether the EQL extension is installed by looking for the `eql_v2` schema.
   */
  async isInstalled(): Promise<boolean> {
    const client = new pg.Client({ connectionString: this.databaseUrl })

    try {
      await client.connect()

      const result = await client.query(
        'SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1',
        [EQL_SCHEMA_NAME],
      )

      return result.rowCount !== null && result.rowCount > 0
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /**
   * Return the installed EQL version, or `null` if EQL is not installed.
   *
   * This is best-effort: if the schema exists but no version metadata is
   * available, `'unknown'` is returned.
   */
  async getInstalledVersion(): Promise<string | null> {
    const client = new pg.Client({ connectionString: this.databaseUrl })

    try {
      await client.connect()

      const schemaResult = await client.query(
        'SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1',
        [EQL_SCHEMA_NAME],
      )

      if (schemaResult.rowCount === null || schemaResult.rowCount === 0) {
        return null
      }

      // Attempt to read a version from the schema — the EQL extension may
      // expose a `version()` function or a `version` table. If neither exists
      // we fall back to 'unknown'.
      try {
        const versionResult = await client.query(
          `SELECT ${EQL_SCHEMA_NAME}.version() AS version`,
        )

        if (versionResult.rows.length > 0 && versionResult.rows[0].version) {
          return String(versionResult.rows[0].version)
        }
      } catch {
        // version() function does not exist — that's fine
      }

      return 'unknown'
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /**
   * Install the CipherStash EQL PostgreSQL extension.
   *
   * By default, uses the SQL bundled with this package. Pass `latest: true`
   * to fetch the latest version from GitHub instead.
   *
   * This method is intentionally "silent" — it does not produce any console
   * output. The calling CLI command is responsible for all user-facing output.
   */
  async install(options?: {
    excludeOperatorFamily?: boolean
    supabase?: boolean
    latest?: boolean
  }): Promise<void> {
    const { supabase = false, latest = false } = options ?? {}
    const excludeOperatorFamily = options?.excludeOperatorFamily || supabase
    const sql = latest
      ? await this.downloadInstallScript(excludeOperatorFamily)
      : this.loadBundledInstallScript({ excludeOperatorFamily, supabase })

    const client = new pg.Client({ connectionString: this.databaseUrl })

    try {
      await client.connect()
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    }

    try {
      await client.query('BEGIN')
      await client.query(sql)

      if (supabase) {
        await this.grantSupabasePermissions(client)
      }

      await client.query('COMMIT')
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {
        // Swallow rollback errors — the original error is more important.
      })

      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to install EQL: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /**
   * Grant Supabase roles access to the eql_v2 schema.
   *
   * Supabase uses dedicated roles (anon, authenticated, service_role) that
   * don't own the schema, so explicit grants are required. Issues
   * {@link SUPABASE_PERMISSIONS_SQL} as a single multi-statement query —
   * Postgres accepts that and it keeps the SQL identical to what we'd write
   * into a Supabase migration file.
   */
  private async grantSupabasePermissions(client: pg.Client): Promise<void> {
    await client.query(SUPABASE_PERMISSIONS_SQL)
  }

  /**
   * Load the EQL SQL install script bundled with this package.
   */
  private loadBundledInstallScript(options: {
    excludeOperatorFamily: boolean
    supabase: boolean
  }): string {
    const filename = resolveBundledFilename(options)

    try {
      return readFileSync(bundledSqlPath(filename), 'utf-8')
    } catch (error) {
      throw new Error(
        `Failed to load bundled EQL install script (${filename}). The package may be corrupted — try reinstalling stash.`,
        { cause: error },
      )
    }
  }

  /**
   * Download the EQL SQL install script from GitHub.
   */
  private async downloadInstallScript(
    excludeOperatorFamily: boolean,
  ): Promise<string> {
    const url = excludeOperatorFamily
      ? EQL_INSTALL_NO_OPERATOR_FAMILY_URL
      : EQL_INSTALL_URL

    let response: Response

    try {
      response = await fetch(url)
    } catch (error) {
      throw new Error('Failed to download EQL install script from GitHub.', {
        cause: error,
      })
    }

    if (!response.ok) {
      throw new Error(
        `Failed to download EQL install script from GitHub. HTTP ${response.status}: ${response.statusText}`,
      )
    }

    return response.text()
  }
}

/**
 * Determine which bundled SQL file to use based on install options.
 *
 * - `supabase: true` → Supabase-specific variant
 * - `excludeOperatorFamily: true` → no operator family variant
 * - default → standard install
 */
function resolveBundledFilename(options: {
  excludeOperatorFamily: boolean
  supabase: boolean
}): string {
  if (options.supabase) return 'cipherstash-encrypt-supabase.sql'
  if (options.excludeOperatorFamily)
    return 'cipherstash-encrypt-no-operator-family.sql'
  return 'cipherstash-encrypt.sql'
}

/**
 * Load the bundled EQL install SQL. Used by the Drizzle migration path.
 */
export function loadBundledEqlSql(
  options: {
    excludeOperatorFamily?: boolean
    supabase?: boolean
  } = {},
): string {
  const filename = resolveBundledFilename({
    excludeOperatorFamily: options.excludeOperatorFamily ?? false,
    supabase: options.supabase ?? false,
  })

  try {
    return readFileSync(bundledSqlPath(filename), 'utf-8')
  } catch (error) {
    throw new Error(
      `Failed to load bundled EQL install script (${filename}). The package may be corrupted — try reinstalling stash.`,
      { cause: error },
    )
  }
}

/**
 * Download the latest EQL install SQL from GitHub. Used by the Drizzle migration path
 * when `--latest` is passed.
 *
 * Supabase uses the same GitHub asset as the no-operator-family variant —
 * treating either flag as "no operator families" keeps the intent explicit
 * even though the underlying URL is the same.
 */
export async function downloadEqlSql(
  options:
    | { excludeOperatorFamily?: boolean; supabase?: boolean }
    | boolean = false,
): Promise<string> {
  const normalized =
    typeof options === 'boolean'
      ? { excludeOperatorFamily: options, supabase: false }
      : {
          excludeOperatorFamily: options.excludeOperatorFamily ?? false,
          supabase: options.supabase ?? false,
        }

  const useNoOperatorFamilyUrl =
    normalized.excludeOperatorFamily || normalized.supabase
  const url = useNoOperatorFamilyUrl
    ? EQL_INSTALL_NO_OPERATOR_FAMILY_URL
    : EQL_INSTALL_URL

  let response: Response

  try {
    response = await fetch(url)
  } catch (error) {
    throw new Error('Failed to download EQL install script from GitHub.', {
      cause: error,
    })
  }

  if (!response.ok) {
    throw new Error(
      `Failed to download EQL install script. HTTP ${response.status}: ${response.statusText}`,
    )
  }

  return response.text()
}
