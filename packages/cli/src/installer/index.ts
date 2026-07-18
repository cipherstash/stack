import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { readInstallSql } from '@cipherstash/eql/sql'
import pg from 'pg'
import {
  EQL_SCHEMA_NAME,
  EQL_V3_INTERNAL_SCHEMA_NAME,
  EQL_V3_SCHEMA_NAME,
  SUPABASE_PERMISSIONS_SQL,
  SUPABASE_PERMISSIONS_SQL_V3,
} from './grants.js'

/**
 * The EQL **v3** install SQL, read from `@cipherstash/eql` at runtime — the
 * single source of truth (the same `readInstallSql()` the stack and prisma-next
 * consume). We deliberately do NOT vendor a copy into the repo:
 *   - a ~44k-line plpgsql artifact in the tree made GitHub classify the whole
 *     repo as plpgsql (CIP-3518);
 *   - a vendored copy silently drifts from the pinned package on every bump.
 * Reading it here means a `@cipherstash/eql` version bump flows straight through.
 * There is no Supabase / no-operator-family variant for v3: the bundle installs
 * everywhere from one artifact (its superuser-only operator-class statements run
 * inside a `DO` block that catches `insufficient_privilege` and skips).
 */
function readV3InstallSql(): string {
  try {
    return readInstallSql()
  } catch (error) {
    throw new Error(
      'Failed to read the EQL v3 install SQL from `@cipherstash/eql`. Reinstall dependencies (the package ships the bundle in `dist/sql/`).',
      { cause: error },
    )
  }
}

// EQL release, pinned to match the EQL payload format this package emits.
// Bump in lockstep with @cipherstash/protect-ffi.
const EQL_VERSION = 'eql-2.3.1'
const EQL_INSTALL_URL = `https://github.com/cipherstash/encrypt-query-language/releases/download/${EQL_VERSION}/cipherstash-encrypt.sql`
const EQL_INSTALL_NO_OPERATOR_FAMILY_URL = `https://github.com/cipherstash/encrypt-query-language/releases/download/${EQL_VERSION}/cipherstash-encrypt-supabase.sql`

// The grants SQL lives in `./grants.ts` (import-free) so the live proof in
// `@cipherstash/stack` can assert against the exact shipped strings without a
// package cycle. Re-exported here: this module stays the public entry point.
export {
  EQL_SCHEMA_NAME,
  EQL_V3_INTERNAL_SCHEMA_NAME,
  EQL_V3_SCHEMA_NAME,
  SUPABASE_PERMISSIONS_SQL,
  SUPABASE_PERMISSIONS_SQL_V3,
  supabaseInternalPermissionsSql,
  supabasePermissionsSql,
} from './grants.js'

/**
 * Which EQL generation to install / inspect. `2` is the composite
 * `eql_v2_encrypted` type; `3` is the native concrete-domain schema
 * (`public.*` domains, `eql_v3` operators).
 */
export type EqlVersion = 2 | 3

/**
 * The generation `stash eql install` / `eql upgrade` target when the user
 * doesn't pass `--eql-version`. v3 (native `eql_v3.*` domain types) is the
 * current default; v2 is opt-in via `--eql-version 2` and is required for the
 * Drizzle / Supabase-migration / `--latest` paths, which v3 doesn't support
 * yet.
 */
export const DEFAULT_EQL_VERSION: EqlVersion = 3

/**
 * Resolve the `--eql-version` CLI string (`'2'` / `'3'` / `undefined`) to a
 * concrete {@link EqlVersion}, applying {@link DEFAULT_EQL_VERSION} for anything
 * that isn't an explicit `'2'`. The single authority for "which generation does
 * a bare invocation target", shared by `eql install` / `eql upgrade` so the
 * default lives in one place rather than being re-inlined as `=== '2' ? 2 : 3`.
 * Assumes the value has already been validated (see `validateInstallFlags`).
 */
export function resolveEqlVersion(eqlVersion?: string): EqlVersion {
  return eqlVersion === '2' ? 2 : DEFAULT_EQL_VERSION
}

function schemaNameFor(eqlVersion: EqlVersion): string {
  return eqlVersion === 3 ? EQL_V3_SCHEMA_NAME : EQL_SCHEMA_NAME
}

/**
 * The grants block for an EQL generation — the ONE source of truth for both the
 * runtime install path ({@link EQLInstaller.grantSupabasePermissions}) and the
 * generated Supabase migration file. Previously the installer rebuilt the block
 * from `supabasePermissionsSql(schemaNameFor(...))`, so a v3-only addition (the
 * `eql_v3_internal` grants) reached the migration file and NOT the database the
 * CLI installs into.
 */
export function supabaseGrantsFor(eqlVersion: EqlVersion): string {
  return eqlVersion === 3
    ? SUPABASE_PERMISSIONS_SQL_V3
    : SUPABASE_PERMISSIONS_SQL
}

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
   * Check whether the EQL extension is installed by looking for its schema
   * (`eql_v3` by default, `eql_v2` when `eqlVersion: 2`).
   */
  async isInstalled(options?: { eqlVersion?: EqlVersion }): Promise<boolean> {
    const client = new pg.Client({ connectionString: this.databaseUrl })
    const eqlVersion = options?.eqlVersion ?? DEFAULT_EQL_VERSION

    try {
      await client.connect()

      // v3 is generation-aware: a pre-alpha.2 install has eql_v3 but no
      // eql_v3_internal (and pins v:2 envelopes in its domain CHECKs) — treat
      // it as NOT installed so an install run replaces it (the bundle opens by
      // dropping both schemas) instead of a stale surface silently accepting
      // wrong-generation wire data.
      const requiredSchemas =
        eqlVersion === 3
          ? [EQL_V3_SCHEMA_NAME, EQL_V3_INTERNAL_SCHEMA_NAME]
          : [EQL_SCHEMA_NAME]

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

  /**
   * Return the installed EQL version, or `null` if EQL is not installed.
   *
   * This is best-effort: if the schema exists but no version metadata is
   * available, `'unknown'` is returned.
   */
  async getInstalledVersion(options?: {
    eqlVersion?: EqlVersion
  }): Promise<string | null> {
    const schemaName = schemaNameFor(options?.eqlVersion ?? DEFAULT_EQL_VERSION)
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

      // Attempt to read a version from the schema — the EQL extension may
      // expose a `version()` function or a `version` table. If neither exists
      // we fall back to 'unknown'.
      try {
        const versionResult = await client.query(
          `SELECT ${schemaName}.version() AS version`,
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
    eqlVersion?: EqlVersion
  }): Promise<void> {
    const {
      supabase = false,
      latest = false,
      eqlVersion = DEFAULT_EQL_VERSION,
    } = options ?? {}
    const excludeOperatorFamily = options?.excludeOperatorFamily || supabase

    if (latest && eqlVersion === 3) {
      // The v3 bundle is read from the pinned `@cipherstash/eql` package (see
      // `readV3InstallSql`), not fetched from a GitHub release, so `--latest`
      // (which downloads a release asset) has no v3 target.
      // Gating --latest behind --eql-version 2 is tracked in #585.
      throw new Error(
        '`--latest` is not supported for EQL v3 yet: no public v3 release artifacts exist. Use the bundled install.',
      )
    }

    const sql = latest
      ? await this.downloadInstallScript(excludeOperatorFamily)
      : this.loadBundledInstallScript({
          excludeOperatorFamily,
          supabase,
          eqlVersion,
        })

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
        await this.grantSupabasePermissions(client, eqlVersion)
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
   * Grant Supabase roles access to the installed EQL schema.
   *
   * Supabase uses dedicated roles (anon, authenticated, service_role) that
   * don't own the schema, so explicit grants are required. Issues the
   * {@link supabaseGrantsFor} block as a single multi-statement query —
   * Postgres accepts that and it keeps the SQL identical to what we'd write
   * into a Supabase migration file.
   */
  private async grantSupabasePermissions(
    client: pg.Client,
    eqlVersion: EqlVersion,
  ): Promise<void> {
    await client.query(supabaseGrantsFor(eqlVersion))
  }

  /**
   * Load the EQL SQL install script bundled with this package.
   */
  private loadBundledInstallScript(options: {
    excludeOperatorFamily: boolean
    supabase: boolean
    eqlVersion: EqlVersion
  }): string {
    // v3 is read from `@cipherstash/eql` at runtime; only v2 is vendored.
    if (options.eqlVersion === 3) return readV3InstallSql()

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
 *
 * EQL v3 (eql-3.0.0+) ships ONE artifact for every target: its only
 * superuser-requiring statements (the ore_block_256 operator class/family)
 * self-skip on `insufficient_privilege`, and the bundle then disables the
 * ORE-backed encrypted domains it cannot support (CIP-3468). So `supabase`
 * and `excludeOperatorFamily` change nothing for v3 — the bundle adapts at
 * install time instead of at file-selection time.
 */
function resolveBundledFilename(options: {
  excludeOperatorFamily: boolean
  supabase: boolean
  eqlVersion?: EqlVersion
}): string {
  // v3 is not vendored — it's read from `@cipherstash/eql` at runtime (see
  // `readV3InstallSql`), so callers route it away before reaching here.
  if ((options.eqlVersion ?? DEFAULT_EQL_VERSION) === 3) {
    throw new Error(
      'resolveBundledFilename is v2-only; v3 SQL comes from `@cipherstash/eql`.',
    )
  }
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
    eqlVersion?: EqlVersion
  } = {},
): string {
  const eqlVersion = options.eqlVersion ?? DEFAULT_EQL_VERSION
  // v3 is read from `@cipherstash/eql` at runtime; only v2 is vendored.
  if (eqlVersion === 3) return readV3InstallSql()

  const filename = resolveBundledFilename({
    excludeOperatorFamily: options.excludeOperatorFamily ?? false,
    supabase: options.supabase ?? false,
    eqlVersion,
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
