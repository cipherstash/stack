import { createPgClient, TlsVerificationError } from '@/db/client.js'
import {
  EqlLifecycleLockTimeoutError,
  EqlReinstallConnectionError,
  EqlReinstallRefusalError,
  restoreDerivedSearchIndexesAroundEqlReplacement,
} from './derived-search-index-restoration.js'
import {
  applySupabaseEqlAccess,
  SUPABASE_PERMISSIONS_SQL_V3,
} from './grants.js'
import {
  assessEqlInstallation,
  type PreflightResult,
} from './installation-state.js'
import { loadVerifiedEqlBundle } from './verify.js'

export {
  loadBundledEqlSql,
  SUPPORTED_PGCRYPTO_SCHEMAS,
} from './eql-bundle.js'

export {
  applySupabaseEqlAccess,
  DEFERRED_GRANTS_HEADER,
  EQL_V3_INTERNAL_SCHEMA_NAME,
  EQL_V3_SCHEMA_NAME,
  emitSupabaseEqlAccessMigration,
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
export type { PreflightResult } from './installation-state.js'

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

export class EQLInstaller {
  private readonly databaseUrl: string

  constructor(options: { databaseUrl: string }) {
    this.databaseUrl = options.databaseUrl
  }

  async preflight(): Promise<PreflightResult> {
    const installation = await assessEqlInstallation({
      databaseUrl: this.databaseUrl,
      includeCapabilities: true,
    })
    if (installation.capabilities.status !== 'assessed') {
      throw new Error('Database capabilities were not assessed')
    }
    return installation.capabilities.preflight
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
    const generation = options?.eqlVersion ?? 3
    const client = createPgClient(this.databaseUrl)
    try {
      await client.connect()
      const result = await client.query<{ installed: boolean }>(
        generation === 2
          ? "SELECT to_regnamespace('eql_v2') IS NOT NULL AS installed"
          : "SELECT to_regnamespace('eql_v3') IS NOT NULL AND to_regnamespace('eql_v3_internal') IS NOT NULL AS installed",
      )
      return result.rows[0]?.installed === true
    } catch (error) {
      if (error instanceof TlsVerificationError) throw error
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
    const generation = options?.eqlVersion ?? 3
    const client = createPgClient(this.databaseUrl)
    try {
      await client.connect()
      const schemaName = `eql_v${generation}`
      const schema = await client.query<{ installed: boolean }>(
        'SELECT to_regnamespace($1) IS NOT NULL AS installed',
        [schemaName],
      )
      if (schema.rows[0]?.installed !== true) return null
      try {
        const result = await client.query<{ version: string }>(
          `SELECT ${schemaName}.version() AS version`,
        )
        return result.rows[0]?.version
          ? String(result.rows[0].version)
          : 'unknown'
      } catch {
        return 'unknown'
      }
    } catch (error) {
      if (error instanceof TlsVerificationError) throw error
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
    // Read and digest-verify BEFORE connecting. A bundle that fails
    // verification must not reach the database at all — not even as an opened
    // connection and a `BEGIN` — so the refusal cannot be read as "something
    // was attempted and rolled back". It also keeps the digest message the
    // whole error, rather than a `detail` interpolated into the install
    // wrapper's transaction narration below.
    const bundle = loadVerifiedEqlBundle()
    try {
      await restoreDerivedSearchIndexesAroundEqlReplacement({
        databaseUrl: this.databaseUrl,
        bundledSql: bundle.sql,
      })
    } catch (error) {
      if (
        error instanceof TlsVerificationError ||
        error instanceof EqlLifecycleLockTimeoutError ||
        error instanceof EqlReinstallConnectionError ||
        error instanceof EqlReinstallRefusalError
      ) {
        throw error
      }
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(
        `Failed to install EQL: ${detail}. Nothing was applied — the install runs in a transaction and was rolled back.`,
        { cause: error },
      )
    }

    if (!options?.supabase) return { deferredGrantsSql: null }

    try {
      return await this.applySupabaseGrants()
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(
        `EQL v3 is installed, but granting the Supabase roles failed: ${detail}. The install itself was NOT rolled back — re-run \`stash eql install --force\` (or plain \`stash eql install\`, which re-applies the grants on an already-installed database).`,
        { cause: error },
      )
    }
  }

  /**
   * Re-apply the Supabase role grants on their own — idempotent, safe to run
   * any number of times. This is how a grants failure after a committed
   * install heals: `stash eql install` calls it on the already-installed
   * path, so a plain re-run recovers without `--force`.
   */
  async applySupabaseGrants(): Promise<InstallResult> {
    const client = createPgClient(this.databaseUrl)
    try {
      await client.connect()
    } catch (error) {
      await client.end().catch(() => {})
      // Already shaped centrally by createPgClient's connect wrapper — the
      // message is self-contained; adding framing would bury the remedy.
      if (error instanceof TlsVerificationError) throw error
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to connect to database: ${detail}`, {
        cause: error,
      })
    }
    try {
      const outcome = await applySupabaseEqlAccess(client)
      return {
        deferredGrantsSql:
          outcome.status === 'applied' ? null : outcome.deferredSql,
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to apply the Supabase role grants: ${detail}`, {
        cause: error,
      })
    } finally {
      await client.end()
    }
  }
}
