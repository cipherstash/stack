import { readInstallSql } from '@cipherstash/eql/sql'
import pg from 'pg'
import {
  DEFERRED_GRANTS_HEADER,
  EQL_V3_INTERNAL_SCHEMA_NAME,
  EQL_V3_SCHEMA_NAME,
  SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
  SUPABASE_IMMEDIATE_GRANTS_SQL_V3,
  SUPABASE_PERMISSIONS_SQL_V3,
} from './grants.js'

export {
  DEFERRED_GRANTS_HEADER,
  EQL_V3_INTERNAL_SCHEMA_NAME,
  EQL_V3_SCHEMA_NAME,
  SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
  SUPABASE_IMMEDIATE_GRANTS_SQL_V3,
  SUPABASE_PERMISSIONS_SQL_V3,
  supabaseInternalPermissionsSql,
  supabasePermissionsSql,
} from './grants.js'

/** EQL generations recognised by read-only installation diagnostics. */
export type EqlVersion = 2 | 3

const EQL_V2_SCHEMA_NAME = 'eql_v2'

/** The pinned EQL v3 install SQL. */
export function loadBundledEqlSql(): string {
  try {
    return readInstallSql()
  } catch (error) {
    throw new Error(
      'Failed to read the EQL v3 install SQL from `@cipherstash/eql`. Reinstall dependencies (the package ships the bundle in `dist/sql/`).',
      { cause: error },
    )
  }
}

/** Supabase grants for the sole installable generation, EQL v3. */
export function supabaseGrantsFor(): string {
  return SUPABASE_PERMISSIONS_SQL_V3
}

/**
 * Read-only database preflight: everything the install needs from the role,
 * gathered before anything is attempted.
 *
 * `missing` lists only the gaps that abort the install. Membership of
 * `postgres` is deliberately NOT one of them — a non-member role installs
 * fine; the installer defers the owner-scoped Supabase default-privilege
 * statements instead (see {@link InstallResult.deferredGrantsSql}).
 */
export interface PreflightResult {
  currentUser: string
  isSuperuser: boolean
  /**
   * Whether `current_user` can run `ALTER DEFAULT PRIVILEGES FOR ROLE
   * postgres`. `null` when the database has no `postgres` role at all.
   */
  memberOfPostgres: boolean | null
  hasDatabaseCreate: boolean
  hasPublicCreate: boolean
  pgcryptoInstalled: boolean
  eqlV3SchemaPresent: boolean
  eqlV3InternalSchemaPresent: boolean
  missing: string[]
  ok: boolean
}

/** What `install()` actually did, beyond succeeding. */
export interface InstallResult {
  /**
   * The owner-scoped `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements
   * that were skipped because the connecting role is not a member of
   * `postgres` (prefixed with the explanatory header comment), or `null` when
   * every grant ran. OPTIONAL from the operator's perspective: they only
   * cover EQL objects created outside stash tooling, and every
   * install/upgrade re-grants all objects — surface the SQL as information,
   * not as a required step.
   */
  deferredGrantsSql: string | null
}

/**
 * One query answering every preflight question. `pg_has_role` is guarded by
 * the `CASE`: it raises on a nonexistent role name, and not every database
 * has a `postgres` role.
 */
const PREFLIGHT_SQL = `
  SELECT
    current_user AS role_name,
    (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser,
    CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres')
         THEN pg_has_role(current_user, 'postgres', 'MEMBER')
    END AS member_of_postgres,
    has_database_privilege(current_user, current_database(), 'CREATE') AS has_database_create,
    has_schema_privilege(current_user, 'public', 'CREATE') AS has_public_create,
    EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') AS pgcrypto_installed,
    EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '${EQL_V3_SCHEMA_NAME}') AS eql_v3_present,
    EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '${EQL_V3_INTERNAL_SCHEMA_NAME}') AS eql_v3_internal_present
`

export class EQLInstaller {
  private readonly databaseUrl: string

  constructor(options: { databaseUrl: string }) {
    this.databaseUrl = options.databaseUrl
  }

  async preflight(): Promise<PreflightResult> {
    const client = new pg.Client({ connectionString: this.databaseUrl })
    try {
      await client.connect()
      const result = await client.query(PREFLIGHT_SQL)
      const row = result.rows[0] ?? {}
      const isSuperuser = row.is_superuser === true
      const hasDatabaseCreate = row.has_database_create === true
      const missing: string[] = []
      if (!isSuperuser) {
        if (!hasDatabaseCreate) {
          missing.push(
            'CREATE on database (required for CREATE SCHEMA and CREATE EXTENSION)',
          )
        }
        if (row.has_public_create !== true) {
          missing.push(
            'CREATE on public schema (required for CREATE DOMAIN public.eql_v3_*)',
          )
        }
        if (row.pgcrypto_installed !== true && !hasDatabaseCreate) {
          missing.push(
            'SUPERUSER or extension owner (required for CREATE EXTENSION pgcrypto)',
          )
        }
      }
      return {
        currentUser: String(row.role_name ?? 'unknown'),
        isSuperuser,
        memberOfPostgres:
          typeof row.member_of_postgres === 'boolean'
            ? row.member_of_postgres
            : null,
        hasDatabaseCreate,
        hasPublicCreate: row.has_public_create === true,
        pgcryptoInstalled: row.pgcrypto_installed === true,
        eqlV3SchemaPresent: row.eql_v3_present === true,
        eqlV3InternalSchemaPresent: row.eql_v3_internal_present === true,
        missing,
        ok: missing.length === 0,
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /** Generation-aware read-only detection retained for legacy diagnostics. */
  async isInstalled(options?: { eqlVersion?: EqlVersion }): Promise<boolean> {
    const client = new pg.Client({ connectionString: this.databaseUrl })
    const requiredSchemas =
      (options?.eqlVersion ?? 3) === 3
        ? [EQL_V3_SCHEMA_NAME, EQL_V3_INTERNAL_SCHEMA_NAME]
        : [EQL_V2_SCHEMA_NAME]
    try {
      await client.connect()
      const result = await client.query(
        'SELECT count(*)::int AS found FROM information_schema.schemata WHERE schema_name = ANY($1)',
        [requiredSchemas],
      )
      return result.rows[0]?.found === requiredSchemas.length
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /** Read-only version diagnostics for current and legacy installs. */
  async getInstalledVersion(options?: {
    eqlVersion?: EqlVersion
  }): Promise<string | null> {
    const schemaName =
      (options?.eqlVersion ?? 3) === 3 ? EQL_V3_SCHEMA_NAME : EQL_V2_SCHEMA_NAME
    const client = new pg.Client({ connectionString: this.databaseUrl })
    try {
      await client.connect()
      const schemaResult = await client.query(
        'SELECT schema_name FROM information_schema.schemata WHERE schema_name = $1',
        [schemaName],
      )
      if (schemaResult.rowCount === null || schemaResult.rowCount === 0) {
        return null
      }
      try {
        const versionResult = await client.query(
          `SELECT ${schemaName}.version() AS version`,
        )
        if (versionResult.rows[0]?.version) {
          return String(versionResult.rows[0].version)
        }
      } catch {
        // Older installs may not expose version().
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
   * Install the pinned EQL v3 bundle, then (in Supabase mode) the role
   * grants.
   *
   * The bundle runs in its own transaction. The grants deliberately run
   * AFTER its COMMIT: they are idempotent and separately re-runnable, so a
   * grants failure must not roll back a working install — one refused
   * statement used to take all ~194 functions down with it. When the
   * connecting role is not a member of `postgres`, the owner-scoped
   * `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements are skipped and
   * returned as optional SQL; the plain `GRANT`s still run, so everything
   * that exists is usable immediately, and stash re-grants on every
   * install/upgrade — the install is complete without them.
   */
  async install(options?: { supabase?: boolean }): Promise<InstallResult> {
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
      try {
        await client.query('BEGIN')
        await client.query(loadBundledEqlSql())
        await client.query('COMMIT')
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {})
        const detail = error instanceof Error ? error.message : String(error)
        throw new Error(
          `Failed to install EQL: ${detail}. Nothing was applied — the install runs in a transaction and was rolled back.`,
          { cause: error },
        )
      }

      if (!options?.supabase) return { deferredGrantsSql: null }

      try {
        const memberResult = await client.query(`
          SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres')
                 THEN pg_has_role(current_user, 'postgres', 'MEMBER')
          END AS member_of_postgres
        `)
        if (memberResult.rows[0]?.member_of_postgres === true) {
          await client.query(SUPABASE_PERMISSIONS_SQL_V3)
          return { deferredGrantsSql: null }
        }
        await client.query(SUPABASE_IMMEDIATE_GRANTS_SQL_V3)
        return {
          deferredGrantsSql:
            DEFERRED_GRANTS_HEADER + SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
        }
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        throw new Error(
          `EQL v3 is installed, but granting the Supabase roles failed: ${detail}. The install itself was NOT rolled back — apply the grants from \`stash eql migration --supabase\`, or re-run \`stash eql install --force\`.`,
          { cause: error },
        )
      }
    } finally {
      await client.end()
    }
  }
}
