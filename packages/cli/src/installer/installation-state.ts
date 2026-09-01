import type pg from 'pg'
import { createPgClient, TlsVerificationError } from '@/db/client.js'
import { SUPPORTED_PGCRYPTO_SCHEMAS } from './eql-bundle.js'
import { EQL_V3_INTERNAL_SCHEMA_NAME, EQL_V3_SCHEMA_NAME } from './grants.js'
import {
  assessEqlSurface,
  type OreStateReading,
  type VerifyReport,
} from './verify.js'

export type InstalledEqlGeneration =
  | { status: 'absent' }
  | { status: 'installed'; version: string | 'unknown' }

export type AssessedOreState =
  | { status: 'absent' }
  | {
      status: 'not-comparable'
      bundleVersion: string
      installedVersion: string | null
    }
  | {
      status: 'observed'
      state:
        | 'indexable'
        | 'fallback'
        | 'incoherent-mixed'
        | 'incoherent-poisoned'
        | 'incoherent-unpoisoned'
      opclassPresent: boolean
      poisonedDomains: number
      expectedPoisoned: number
    }

export type AssessedEqlSurface =
  | { status: 'not-requested' }
  | { status: 'not-comparable'; report: VerifyReport }
  | { status: 'complete'; report: VerifyReport }
  | { status: 'damaged'; report: VerifyReport }

export interface EqlInstallationState {
  v2: InstalledEqlGeneration
  v3: InstalledEqlGeneration
  ore: AssessedOreState
  surface: AssessedEqlSurface
  capabilities:
    | { status: 'not-requested' }
    | { status: 'assessed'; preflight: PreflightResult }
}

export interface PreflightResult {
  currentUser: string
  isSuperuser: boolean
  memberOfPostgres: boolean | null
  hasDatabaseCreate: boolean
  hasPublicCreate: boolean
  pgcryptoInstalled: boolean
  pgcryptoSchema: string | null
  eqlV3SchemaPresent: boolean
  eqlV3InternalSchemaPresent: boolean
  canDropEqlV3Schema: boolean | null
  canDropEqlV3InternalSchema: boolean | null
  canCreateOperatorClass: boolean | null
  missing: string[]
  ok: boolean
}

const CAPABILITIES_SQL = `
  SELECT current_user AS role_name,
    (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser,
    CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres') THEN pg_has_role(current_user, 'postgres', 'MEMBER') END AS member_of_postgres,
    has_database_privilege(current_user, current_database(), 'CREATE') AS has_database_create,
    CASE WHEN EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'public') THEN has_schema_privilege(current_user, 'public', 'CREATE') ELSE false END AS has_public_create,
    EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') AS pgcrypto_installed,
    (SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'pgcrypto') AS pgcrypto_schema,
    EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '${EQL_V3_SCHEMA_NAME}') AS eql_v3_present,
    EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '${EQL_V3_INTERNAL_SCHEMA_NAME}') AS eql_v3_internal_present,
    (SELECT pg_has_role(current_user, n.nspowner, 'MEMBER') FROM pg_namespace n WHERE n.nspname = '${EQL_V3_SCHEMA_NAME}') AS can_drop_eql_v3,
    (SELECT pg_has_role(current_user, n.nspowner, 'MEMBER') FROM pg_namespace n WHERE n.nspname = '${EQL_V3_INTERNAL_SCHEMA_NAME}') AS can_drop_eql_v3_internal
`

export async function assessEqlInstallation(options: {
  databaseUrl: string
  depth?: 'summary' | 'exhaustive'
  includeCapabilities?: boolean
}): Promise<EqlInstallationState> {
  const client = createPgClient(options.databaseUrl)
  try {
    await client.connect()
  } catch (error) {
    await client.end().catch(() => {})
    if (error instanceof TlsVerificationError) throw error
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(`Failed to connect to database: ${detail}`, {
      cause: error,
    })
  }

  try {
    await client.query('BEGIN READ ONLY')
    const presence = await client.query<{
      eql_v2_present: boolean
      eql_v3_present: boolean
      eql_v3_internal_present: boolean
    }>(`
      SELECT
        to_regnamespace('eql_v2') IS NOT NULL AS eql_v2_present,
        to_regnamespace('eql_v3') IS NOT NULL AS eql_v3_present,
        to_regnamespace('eql_v3_internal') IS NOT NULL AS eql_v3_internal_present
    `)
    const row = presence.rows[0]
    const v2Present = row?.eql_v2_present === true
    const v3Present =
      row?.eql_v3_present === true && row.eql_v3_internal_present === true
    const v2 = v2Present
      ? { status: 'installed' as const, version: await readVersion(client, 2) }
      : { status: 'absent' as const }
    const v3 = v3Present
      ? { status: 'installed' as const, version: await readVersion(client, 3) }
      : { status: 'absent' as const }

    const verification = v3Present
      ? await assessEqlSurface(
          client,
          options.depth === 'exhaustive' ? 'exhaustive' : 'summary',
        )
      : null
    const ore =
      verification?.depth === 'summary'
        ? assessOre(verification.ore)
        : verification?.report.ore
          ? { status: 'observed' as const, ...verification.report.ore }
          : v3Present && verification?.report.status === 'version-mismatch'
            ? {
                status: 'not-comparable' as const,
                bundleVersion: verification.report.bundleVersion,
                installedVersion: verification.report.installedVersion,
              }
            : { status: 'absent' as const }
    let surface: AssessedEqlSurface = { status: 'not-requested' }
    if (verification?.depth === 'exhaustive') {
      const report = verification.report
      surface =
        report.status === 'version-mismatch'
          ? { status: 'not-comparable', report }
          : report.ok
            ? { status: 'complete', report }
            : { status: 'damaged', report }
    }
    const capabilityRow = options.includeCapabilities
      ? ((await client.query(CAPABILITIES_SQL)).rows[0] ?? {})
      : null
    await client.query('COMMIT')
    const capabilities = capabilityRow
      ? {
          status: 'assessed' as const,
          preflight: buildPreflight(
            capabilityRow,
            await probeOperatorClassCreate(client),
          ),
        }
      : { status: 'not-requested' as const }
    return { v2, v3, ore, surface, capabilities }
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {})
    throw error
  } finally {
    await client.end()
  }
}

function buildPreflight(
  row: Record<string, unknown>,
  canCreateOperatorClass: boolean | null,
): PreflightResult {
  const asBoolOrNull = (value: unknown) =>
    typeof value === 'boolean' ? value : null
  const isSuperuser = row.is_superuser === true
  const hasDatabaseCreate = row.has_database_create === true
  const pgcryptoInstalled = row.pgcrypto_installed === true
  const pgcryptoSchema =
    typeof row.pgcrypto_schema === 'string' ? row.pgcrypto_schema : null
  const canDropEqlV3Schema = asBoolOrNull(row.can_drop_eql_v3)
  const canDropEqlV3InternalSchema = asBoolOrNull(row.can_drop_eql_v3_internal)
  const missing: string[] = []
  if (!isSuperuser) {
    if (!hasDatabaseCreate)
      missing.push(
        'CREATE on database (required for CREATE SCHEMA and CREATE EXTENSION)',
      )
    if (row.has_public_create !== true)
      missing.push(
        'CREATE on public schema (required for CREATE DOMAIN public.eql_v3_*)',
      )
    if (!pgcryptoInstalled && !hasDatabaseCreate)
      missing.push(
        'SUPERUSER or extension owner (required for CREATE EXTENSION pgcrypto)',
      )
  }
  if (
    pgcryptoInstalled &&
    pgcryptoSchema !== null &&
    !SUPPORTED_PGCRYPTO_SCHEMAS.includes(pgcryptoSchema)
  )
    missing.push(
      `pgcrypto relocated (it is in schema "${pgcryptoSchema}", which is not on the EQL search_path — the install aborts; fix with: ALTER EXTENSION pgcrypto SET SCHEMA extensions)`,
    )
  if (canDropEqlV3Schema === false || canDropEqlV3InternalSchema === false)
    missing.push(
      'ownership of the existing EQL schemas (a reinstall begins with DROP SCHEMA eql_v3 / eql_v3_internal CASCADE, which needs the owner, a member of the owning role, or a superuser)',
    )
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
    canCreateOperatorClass,
    missing,
    ok: missing.length === 0,
  }
}

async function probeOperatorClassCreate(
  client: pg.ClientBase,
): Promise<boolean | null> {
  const probeName = 'public.stash_preflight_opclass_probe'
  try {
    await client.query('BEGIN')
  } catch {
    return null
  }
  try {
    await client.query(`CREATE OPERATOR FAMILY ${probeName} USING btree`)
    return true
  } catch (error) {
    const code =
      typeof error === 'object' && error !== null && 'code' in error
        ? String((error as { code?: unknown }).code)
        : undefined
    return code === '42501' ? false : null
  } finally {
    await client.query('ROLLBACK').catch(() => {})
  }
}

async function readVersion(
  client: {
    query: (sql: string) => Promise<{ rows: Array<{ version?: unknown }> }>
  },
  generation: 2 | 3,
): Promise<string | 'unknown'> {
  try {
    const result = await client.query(
      `SELECT eql_v${generation}.version() AS version`,
    )
    return result.rows[0]?.version ? String(result.rows[0].version) : 'unknown'
  } catch {
    return 'unknown'
  }
}

function assessOre(ore: OreStateReading): AssessedOreState {
  return ore.comparable
    ? { status: 'observed', ...ore }
    : { status: 'not-comparable', ...ore }
}
