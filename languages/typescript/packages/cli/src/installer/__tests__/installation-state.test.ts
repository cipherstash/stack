import { releaseManifest } from '@cipherstash/eql/sql'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const query = vi.fn()
const connect = vi.fn()
const end = vi.fn()

vi.mock('@/db/client.js', () => ({
  createPgClient: () => ({ query, connect, end }),
  TlsVerificationError: class extends Error {},
}))

describe('EQL installation state', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    connect.mockResolvedValue(undefined)
    end.mockResolvedValue(undefined)
  })

  it('recovers from a missing version function before continuing its snapshot', async () => {
    let aborted = false
    query.mockImplementation(async (sql: string) => {
      if (sql.includes("to_regnamespace('eql_v2')")) {
        return {
          rows: [
            {
              eql_v2_present: true,
              eql_v3_present: false,
              eql_v3_internal_present: false,
            },
          ],
        }
      }
      if (sql.includes('eql_v2.version()')) {
        aborted = true
        throw Object.assign(new Error('undefined function'), { code: '42883' })
      }
      if (sql === 'ROLLBACK TO SAVEPOINT eql_version_probe') {
        aborted = false
        return { rows: [] }
      }
      if (aborted) {
        throw Object.assign(new Error('transaction is aborted'), {
          code: '25P02',
        })
      }
      return { rows: [] }
    })

    const { assessEqlInstallation } = await import('../installation-state.js')
    const state = await assessEqlInstallation({
      databaseUrl: 'postgres://test',
    })

    expect(state.v2).toEqual({ status: 'installed', version: 'unknown' })
    expect(query).toHaveBeenCalledWith(
      'ROLLBACK TO SAVEPOINT eql_version_probe',
    )
    expect(query).toHaveBeenCalledWith('COMMIT')
  })

  it('recovers when exhaustive surface observation finds a missing version function', async () => {
    let versionReads = 0
    let aborted = false
    query.mockImplementation(async (sql: string) => {
      if (sql.includes("to_regnamespace('eql_v2')")) {
        return {
          rows: [
            {
              eql_v2_present: false,
              eql_v3_present: true,
              eql_v3_internal_present: true,
            },
          ],
        }
      }
      if (sql.includes('eql_v3.version()')) {
        versionReads += 1
        if (versionReads === 1)
          return { rows: [{ version: releaseManifest.eqlVersion }] }
        aborted = true
        throw Object.assign(new Error('undefined function'), { code: '42883' })
      }
      if (sql === 'ROLLBACK TO SAVEPOINT installed_eql_version_probe') {
        aborted = false
        return { rows: [] }
      }
      if (aborted)
        throw Object.assign(new Error('transaction is aborted'), {
          code: '25P02',
        })
      if (sql.includes('pgcrypto_installed')) {
        return {
          rows: [
            {
              eql_v3_present: true,
              eql_v3_internal_present: true,
              pgcrypto_installed: true,
              pgcrypto_schema: 'public',
            },
          ],
        }
      }
      if (sql.includes('ore_opclass_present')) {
        return { rows: [{ ore_opclass_present: true, poisoned_domains: 0 }] }
      }
      return { rows: [] }
    })

    const { assessEqlInstallation } = await import('../installation-state.js')
    const state = await assessEqlInstallation({
      databaseUrl: 'postgres://test',
      depth: 'exhaustive',
    })

    expect(state.surface.status).toBe('damaged')
    expect(query).toHaveBeenCalledWith(
      'ROLLBACK TO SAVEPOINT installed_eql_version_probe',
    )
    expect(query).toHaveBeenCalledWith('COMMIT')
  })

  it('reports an unavailable advisory ORE observation without failing installation state', async () => {
    query.mockImplementation(async (sql: string) => {
      if (sql.includes("to_regnamespace('eql_v2')")) {
        return {
          rows: [
            {
              eql_v2_present: false,
              eql_v3_present: true,
              eql_v3_internal_present: true,
            },
          ],
        }
      }
      if (sql.includes('eql_v3.version()'))
        return { rows: [{ version: releaseManifest.eqlVersion }] }
      if (sql.includes('ore_opclass_present'))
        throw new Error('catalog unavailable')
      return { rows: [] }
    })

    const { assessEqlInstallation } = await import('../installation-state.js')
    const state = await assessEqlInstallation({
      databaseUrl: 'postgres://test',
      includeOre: true,
    })

    expect(state.ore).toEqual({
      status: 'unavailable',
      message: 'catalog unavailable',
    })
    expect(query).toHaveBeenCalledWith('COMMIT')
  })

  it('reports one authoritative schema-presence observation across installation and capabilities', async () => {
    query.mockImplementation(async (sql: string) => {
      if (sql.includes("to_regnamespace('eql_v2')")) {
        return {
          rows: [
            {
              eql_v2_present: false,
              eql_v3_present: true,
              eql_v3_internal_present: true,
            },
          ],
        }
      }
      if (sql.includes('eql_v3.version()'))
        return { rows: [{ version: releaseManifest.eqlVersion }] }
      if (sql.includes('current_user AS role_name')) {
        return {
          rows: [
            {
              role_name: 'restricted_role',
              is_superuser: false,
              member_of_postgres: false,
              has_database_create: true,
              has_public_create: true,
              pgcrypto_installed: true,
              pgcrypto_schema: 'public',
              // information_schema can hide schemas that to_regnamespace sees.
              eql_v3_present: false,
              eql_v3_internal_present: false,
              can_drop_eql_v3: false,
              can_drop_eql_v3_internal: false,
            },
          ],
        }
      }
      return { rows: [] }
    })

    const { assessEqlInstallation } = await import('../installation-state.js')
    const state = await assessEqlInstallation({
      databaseUrl: 'postgres://test',
      includeCapabilities: true,
    })

    expect(state.v3.status).toBe('installed')
    expect(state.capabilities).toMatchObject({
      status: 'assessed',
      preflight: {
        eqlV3SchemaPresent: true,
        eqlV3InternalSchemaPresent: true,
      },
    })
  })

  it('exhaustively reports a missing EQL installation', async () => {
    query.mockImplementation(async (sql: string) => {
      if (sql.includes("to_regnamespace('eql_v2')")) {
        return {
          rows: [
            {
              eql_v2_present: false,
              eql_v3_present: false,
              eql_v3_internal_present: false,
            },
          ],
        }
      }
      if (sql.includes('pgcrypto_installed')) {
        return {
          rows: [
            {
              eql_v3_present: false,
              eql_v3_internal_present: false,
              pgcrypto_installed: false,
              pgcrypto_schema: null,
            },
          ],
        }
      }
      return { rows: [] }
    })

    const { assessEqlInstallation } = await import('../installation-state.js')
    const state = await assessEqlInstallation({
      databaseUrl: 'postgres://test',
      depth: 'exhaustive',
    })

    expect(state.surface.status).toBe('damaged')
    if (state.surface.status !== 'damaged') return
    expect(state.surface.report.status).toBe('not-installed')
  })
})
