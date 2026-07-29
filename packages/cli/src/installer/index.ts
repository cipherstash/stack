import { readInstallSql } from '@cipherstash/eql/sql'
import pg from 'pg'
import {
  EQL_V3_INTERNAL_SCHEMA_NAME,
  EQL_V3_SCHEMA_NAME,
  SUPABASE_PERMISSIONS_SQL_V3,
} from './grants.js'

export {
  EQL_V3_INTERNAL_SCHEMA_NAME,
  EQL_V3_SCHEMA_NAME,
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

export interface PermissionCheckResult {
  ok: boolean
  missing: string[]
  isSuperuser: boolean
}

export class EQLInstaller {
  private readonly databaseUrl: string

  constructor(options: { databaseUrl: string }) {
    this.databaseUrl = options.databaseUrl
  }

  async checkPermissions(): Promise<PermissionCheckResult> {
    const client = new pg.Client({ connectionString: this.databaseUrl })
    try {
      await client.connect()
      const missing: string[] = []
      const roleResult = await client.query(`
        SELECT rolsuper, rolcreatedb
        FROM pg_roles
        WHERE rolname = current_user
      `)
      const role = roleResult.rows[0]
      const isSuperuser = role?.rolsuper === true
      if (isSuperuser) return { ok: true, missing: [], isSuperuser: true }

      const dbCreateResult = await client.query(`
        SELECT has_database_privilege(current_user, current_database(), 'CREATE') AS has_create
      `)
      if (!dbCreateResult.rows[0]?.has_create) {
        missing.push(
          'CREATE on database (required for CREATE SCHEMA and CREATE EXTENSION)',
        )
      }

      const schemaCreateResult = await client.query(`
        SELECT has_schema_privilege(current_user, 'public', 'CREATE') AS has_create
      `)
      if (!schemaCreateResult.rows[0]?.has_create) {
        missing.push(
          'CREATE on public schema (required for CREATE DOMAIN public.eql_v3_*)',
        )
      }

      const pgcryptoResult = await client.query(`
        SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
      `)
      if (
        (pgcryptoResult.rowCount === 0 || pgcryptoResult.rowCount === null) &&
        !dbCreateResult.rows[0]?.has_create
      ) {
        missing.push(
          'SUPERUSER or extension owner (required for CREATE EXTENSION pgcrypto)',
        )
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

  /** Install the pinned EQL v3 bundle. */
  async install(options?: { supabase?: boolean }): Promise<void> {
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
      await client.query(loadBundledEqlSql())
      if (options?.supabase) {
        await client.query(SUPABASE_PERMISSIONS_SQL_V3)
      }
      await client.query('COMMIT')
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {})
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to install EQL: ${detail}`, { cause: error })
    } finally {
      await client.end()
    }
  }
}
