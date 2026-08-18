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
  SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3,
  SUPABASE_IMMEDIATE_GRANTS_SQL_V3,
  SUPABASE_MIGRATION_GRANTS_SQL_V3,
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
  /**
   * The schema `pgcrypto` lives in, or `null` when not installed. The pinned
   * bundle accepts `extensions` and `public` (its functions' search_path) and
   * ABORTS for any other schema — so an unsupported placement blocks even a
   * superuser.
   */
  pgcryptoSchema: string | null
  eqlV3SchemaPresent: boolean
  eqlV3InternalSchemaPresent: boolean
  /**
   * Whether `current_user` may drop the existing `eql_v3` / `eql_v3_internal`
   * schemas (owner, member of the owning role, or superuser). `null` when the
   * schema is absent. Matters because a reinstall begins with
   * `DROP SCHEMA ... CASCADE`.
   */
  canDropEqlV3Schema: boolean | null
  canDropEqlV3InternalSchema: boolean | null
  missing: string[]
  ok: boolean
}

/**
 * The legacy permission-check shape.
 * @deprecated Use {@link EQLInstaller.preflight} and {@link PreflightResult};
 * this remains only so existing `stash@1.x` consumers keep compiling.
 */
export interface PermissionCheckResult {
  ok: boolean
  missing: string[]
  isSuperuser: boolean
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
 * One query answering every preflight question. Two guard patterns are
 * load-bearing: `pg_has_role` raises on a nonexistent role name (not every
 * database has a `postgres` role), and `has_schema_privilege` raises 3F000 on
 * a nonexistent schema (hardened databases drop `public`) — each probe that
 * can raise is wrapped so a missing object reads as a capability answer, not
 * a query failure. The scalar subqueries against `pg_namespace` return NULL
 * (not an error) when the schema is absent, which maps to the `null` arms of
 * {@link PreflightResult}.
 */
const PREFLIGHT_SQL = `
  SELECT
    current_user AS role_name,
    (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser,
    CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres')
         THEN pg_has_role(current_user, 'postgres', 'MEMBER')
    END AS member_of_postgres,
    has_database_privilege(current_user, current_database(), 'CREATE') AS has_database_create,
    CASE WHEN EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'public')
         THEN has_schema_privilege(current_user, 'public', 'CREATE')
         ELSE false
    END AS has_public_create,
    EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') AS pgcrypto_installed,
    (SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
      WHERE e.extname = 'pgcrypto') AS pgcrypto_schema,
    EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '${EQL_V3_SCHEMA_NAME}') AS eql_v3_present,
    EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '${EQL_V3_INTERNAL_SCHEMA_NAME}') AS eql_v3_internal_present,
    (SELECT pg_has_role(current_user, n.nspowner, 'MEMBER') FROM pg_namespace n
      WHERE n.nspname = '${EQL_V3_SCHEMA_NAME}') AS can_drop_eql_v3,
    (SELECT pg_has_role(current_user, n.nspowner, 'MEMBER') FROM pg_namespace n
      WHERE n.nspname = '${EQL_V3_INTERNAL_SCHEMA_NAME}') AS can_drop_eql_v3_internal
`

/** The schemas the pinned bundle accepts `pgcrypto` in (its search_path). */
const SUPPORTED_PGCRYPTO_SCHEMAS = ['extensions', 'public']

export class EQLInstaller {
  private readonly databaseUrl: string

  constructor(options: { databaseUrl: string }) {
    this.databaseUrl = options.databaseUrl
  }

  async preflight(): Promise<PreflightResult> {
    const client = new pg.Client({ connectionString: this.databaseUrl })
    try {
      await client.connect()
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      await client.end().catch(() => {})
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    }
    try {
      const result = await client.query(PREFLIGHT_SQL)
      const row = result.rows[0] ?? {}
      const isSuperuser = row.is_superuser === true
      const hasDatabaseCreate = row.has_database_create === true
      const pgcryptoInstalled = row.pgcrypto_installed === true
      const pgcryptoSchema =
        typeof row.pgcrypto_schema === 'string' ? row.pgcrypto_schema : null
      const asBoolOrNull = (value: unknown) =>
        typeof value === 'boolean' ? value : null
      const canDropEqlV3Schema = asBoolOrNull(row.can_drop_eql_v3)
      const canDropEqlV3InternalSchema = asBoolOrNull(
        row.can_drop_eql_v3_internal,
      )
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
        if (!pgcryptoInstalled && !hasDatabaseCreate) {
          missing.push(
            'SUPERUSER or extension owner (required for CREATE EXTENSION pgcrypto)',
          )
        }
      }
      // Not gated on superuser: the bundle itself raises for a pgcrypto
      // outside its functions' search_path, whoever runs it.
      if (
        pgcryptoInstalled &&
        pgcryptoSchema !== null &&
        !SUPPORTED_PGCRYPTO_SCHEMAS.includes(pgcryptoSchema)
      ) {
        missing.push(
          `pgcrypto relocated (it is in schema "${pgcryptoSchema}", which is not on the EQL search_path — the install aborts; fix with: ALTER EXTENSION pgcrypto SET SCHEMA extensions)`,
        )
      }
      // pg_has_role is true for superusers and for the owner, so this only
      // fires for a role that genuinely cannot run the bundle's opening
      // DROP SCHEMA ... CASCADE against someone else's install.
      if (
        canDropEqlV3Schema === false ||
        canDropEqlV3InternalSchema === false
      ) {
        missing.push(
          'ownership of the existing EQL schemas (a reinstall begins with DROP SCHEMA eql_v3 / eql_v3_internal CASCADE, which needs the owner, a member of the owning role, or a superuser)',
        )
      }
      return {
        currentUser: String(row.role_name ?? 'unknown'),
        isSuperuser,
        memberOfPostgres: asBoolOrNull(row.member_of_postgres),
        hasDatabaseCreate,
        hasPublicCreate: row.has_public_create === true,
        pgcryptoInstalled,
        pgcryptoSchema,
        eqlV3SchemaPresent: row.eql_v3_present === true,
        eqlV3InternalSchemaPresent: row.eql_v3_internal_present === true,
        canDropEqlV3Schema,
        canDropEqlV3InternalSchema,
        missing,
        ok: missing.length === 0,
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Database preflight query failed: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /**
   * The legacy permission check.
   * @deprecated Use {@link preflight}; this thin adapter exists only so
   * existing `stash@1.x` consumers keep working, and will be removed in the
   * next major.
   */
  async checkPermissions(): Promise<PermissionCheckResult> {
    const result = await this.preflight()
    return {
      ok: result.ok,
      missing: result.missing,
      isSuperuser: result.isSuperuser,
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
        return await this.runSupabaseGrants(client)
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        throw new Error(
          `EQL v3 is installed, but granting the Supabase roles failed: ${detail}. The install itself was NOT rolled back — re-run \`stash eql install --force\` (or plain \`stash eql install\`, which re-applies the grants on an already-installed database).`,
          { cause: error },
        )
      }
    } finally {
      await client.end()
    }
  }

  /**
   * Re-apply the Supabase role grants on their own — idempotent, safe to run
   * any number of times. This is how a grants failure after a committed
   * install heals: `stash eql install` calls it on the already-installed
   * path, so a plain re-run recovers without `--force`.
   */
  async applySupabaseGrants(): Promise<InstallResult> {
    const client = new pg.Client({ connectionString: this.databaseUrl })
    try {
      await client.connect()
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      await client.end().catch(() => {})
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    }
    try {
      return await this.runSupabaseGrants(client)
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to apply the Supabase role grants: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }

  /** The shared grants phase: full block for members, immediate half + deferred tail otherwise. */
  private async runSupabaseGrants(client: pg.Client): Promise<InstallResult> {
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
  }
}
