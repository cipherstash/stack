import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mockConnect = vi.fn()
const mockQuery = vi.fn()
const mockEnd = vi.fn()

vi.mock('pg', () => ({
  default: {
    Client: vi.fn(() => ({
      connect: mockConnect,
      query: mockQuery,
      end: mockEnd,
    })),
  },
}))

/** A full preflight row with every capability present. */
const CAPABLE_ROW = {
  role_name: 'postgres',
  is_superuser: true,
  member_of_postgres: true,
  has_database_create: true,
  has_public_create: true,
  pgcrypto_installed: true,
  pgcrypto_schema: 'extensions',
  eql_v3_present: false,
  eql_v3_internal_present: false,
  can_drop_eql_v3: null,
  can_drop_eql_v3_internal: null,
}

describe('EQLInstaller', () => {
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => vi.restoreAllMocks())

  it('reports a fully-capable superuser with no gaps', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({ rows: [CAPABLE_ROW], rowCount: 1 })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.preflight()).resolves.toMatchObject({
      ok: true,
      missing: [],
      isSuperuser: true,
      memberOfPostgres: true,
      currentUser: 'postgres',
    })
  })

  it('accepts database-local CREATE privilege for installing pgcrypto', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({
      rows: [
        {
          ...CAPABLE_ROW,
          role_name: 'app',
          is_superuser: false,
          member_of_postgres: false,
          pgcrypto_installed: false,
        },
      ],
      rowCount: 1,
    })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.preflight()).resolves.toMatchObject({
      ok: true,
      missing: [],
      isSuperuser: false,
      memberOfPostgres: false,
    })
  })

  it('names each blocking gap for an under-privileged role', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({
      rows: [
        {
          role_name: 'sandbox_exec',
          is_superuser: false,
          member_of_postgres: false,
          has_database_create: false,
          has_public_create: false,
          pgcrypto_installed: false,
          eql_v3_present: false,
          eql_v3_internal_present: false,
        },
      ],
      rowCount: 1,
    })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    const result = await installer.preflight()
    expect(result.ok).toBe(false)
    expect(result.missing).toEqual([
      'CREATE on database (required for CREATE SCHEMA and CREATE EXTENSION)',
      'CREATE on public schema (required for CREATE DOMAIN public.eql_v3_*)',
      'SUPERUSER or extension owner (required for CREATE EXTENSION pgcrypto)',
    ])
  })

  it('reports null membership when the database has no postgres role', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({
      rows: [
        {
          ...CAPABLE_ROW,
          is_superuser: false,
          member_of_postgres: null,
        },
      ],
      rowCount: 1,
    })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.preflight()).resolves.toMatchObject({
      memberOfPostgres: null,
      ok: true,
    })
  })

  it('blocks a relocated pgcrypto, even for a superuser', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({
      rows: [{ ...CAPABLE_ROW, pgcrypto_schema: 'crypto_home' }],
      rowCount: 1,
    })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    const result = await installer.preflight()
    expect(result.ok).toBe(false)
    expect(result.missing).toEqual([
      expect.stringContaining('pgcrypto relocated'),
    ])
    expect(result.missing[0]).toContain('crypto_home')
    expect(result.missing[0]).toContain('ALTER EXTENSION pgcrypto SET SCHEMA')
  })

  it('accepts pgcrypto in either supported schema', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })
    for (const schema of ['extensions', 'public']) {
      mockQuery.mockResolvedValue({
        rows: [{ ...CAPABLE_ROW, pgcrypto_schema: schema }],
        rowCount: 1,
      })
      await expect(installer.preflight()).resolves.toMatchObject({
        ok: true,
        pgcryptoSchema: schema,
      })
    }
  })

  it('blocks a role that cannot drop an existing EQL schema', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({
      rows: [
        {
          ...CAPABLE_ROW,
          role_name: 'other_admin',
          is_superuser: false,
          member_of_postgres: false,
          eql_v3_present: true,
          eql_v3_internal_present: true,
          can_drop_eql_v3: false,
          can_drop_eql_v3_internal: false,
        },
      ],
      rowCount: 1,
    })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    const result = await installer.preflight()
    expect(result.ok).toBe(false)
    expect(result.missing).toEqual([
      expect.stringContaining('ownership of the existing EQL schemas'),
    ])
    expect(result.canDropEqlV3Schema).toBe(false)
  })

  it('keeps the deprecated checkPermissions() adapter shape', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({ rows: [CAPABLE_ROW], rowCount: 1 })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.checkPermissions()).resolves.toEqual({
      ok: true,
      missing: [],
      isSuperuser: true,
    })
  })

  it('requires both EQL v3 schemas for the current install', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    mockQuery.mockResolvedValue({ rows: [{ found: 2 }], rowCount: 1 })
    await expect(installer.isInstalled()).resolves.toBe(true)
    expect(mockQuery).toHaveBeenCalledWith(expect.any(String), [
      ['eql_v3', 'eql_v3_internal'],
    ])

    mockQuery.mockResolvedValue({ rows: [{ found: 1 }], rowCount: 1 })
    await expect(installer.isInstalled()).resolves.toBe(false)
  })

  it('retains read-only EQL v2 installation detection for status', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockEnd.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({ rows: [{ found: 1 }], rowCount: 1 })
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.isInstalled({ eqlVersion: 2 })).resolves.toBe(true)
    expect(mockQuery).toHaveBeenCalledWith(expect.any(String), [['eql_v2']])
  })

  it('installs only the pinned EQL v3 bundle', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.install()).resolves.toEqual({
      deferredGrantsSql: null,
    })

    const sqlCall = mockQuery.mock.calls.find(
      ([sql]) =>
        typeof sql === 'string' &&
        !['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql),
    )
    expect(sqlCall?.[0]).toContain('eql_v3')
    expect(sqlCall?.[0]).not.toContain('CREATE SCHEMA eql_v2')
    expect(mockQuery).toHaveBeenCalledWith('COMMIT')
  })

  it('grants both EQL v3 schemas to Supabase roles when the role is a member of postgres', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockImplementation((sql: string) => {
      if (typeof sql === 'string' && sql.includes('member_of_postgres')) {
        return Promise.resolve({
          rows: [{ member_of_postgres: true }],
          rowCount: 1,
        })
      }
      return Promise.resolve({ rows: [], rowCount: 0 })
    })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller, SUPABASE_PERMISSIONS_SQL_V3 } = await import(
      '@/installer/index.ts'
    )
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.install({ supabase: true })).resolves.toEqual({
      deferredGrantsSql: null,
    })

    expect(mockQuery).toHaveBeenCalledWith(SUPABASE_PERMISSIONS_SQL_V3)
    expect(SUPABASE_PERMISSIONS_SQL_V3).toContain('eql_v3_internal')
    expect(SUPABASE_PERMISSIONS_SQL_V3).not.toContain('eql_v2')
  })

  it('defers the owner-scoped grants when the role is not a member of postgres', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockImplementation((sql: string) => {
      if (typeof sql === 'string' && sql.includes('member_of_postgres')) {
        return Promise.resolve({
          rows: [{ member_of_postgres: false }],
          rowCount: 1,
        })
      }
      return Promise.resolve({ rows: [], rowCount: 0 })
    })
    mockEnd.mockResolvedValue(undefined)
    const {
      EQLInstaller,
      SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
      SUPABASE_IMMEDIATE_GRANTS_SQL_V3,
      SUPABASE_PERMISSIONS_SQL_V3,
    } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    const result = await installer.install({ supabase: true })

    expect(mockQuery).toHaveBeenCalledWith(SUPABASE_IMMEDIATE_GRANTS_SQL_V3)
    expect(mockQuery).not.toHaveBeenCalledWith(SUPABASE_PERMISSIONS_SQL_V3)
    expect(mockQuery).not.toHaveBeenCalledWith(
      SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
    )
    expect(result.deferredGrantsSql).toContain(
      'require a role that is a member of `postgres`',
    )
    expect(result.deferredGrantsSql).toContain(
      SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
    )
    // Nothing owner-scoped in what ran; nothing plain-GRANT in what deferred.
    expect(SUPABASE_IMMEDIATE_GRANTS_SQL_V3).not.toContain(
      'ALTER DEFAULT PRIVILEGES',
    )
    expect(SUPABASE_DEFAULT_PRIVILEGES_SQL_V3).not.toContain(
      'GRANT USAGE ON SCHEMA',
    )
  })

  it('rolls back when the install SQL fails, and says so', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockEnd.mockResolvedValue(undefined)
    mockQuery.mockImplementation((sql: string) => {
      if (!['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) {
        return Promise.reject(new Error('permission denied'))
      }
      return Promise.resolve({ rows: [], rowCount: 0 })
    })
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.install()).rejects.toThrow(
      /Failed to install EQL.*rolled back/s,
    )
    expect(mockQuery).toHaveBeenCalledWith('ROLLBACK')
  })

  it('does not roll back the committed bundle when a grant fails', async () => {
    const { EQLInstaller, SUPABASE_PERMISSIONS_SQL_V3 } = await import(
      '@/installer/index.ts'
    )
    mockConnect.mockResolvedValue(undefined)
    mockEnd.mockResolvedValue(undefined)
    mockQuery.mockImplementation((sql: string) => {
      if (typeof sql === 'string' && sql.includes('member_of_postgres')) {
        return Promise.resolve({
          rows: [{ member_of_postgres: true }],
          rowCount: 1,
        })
      }
      if (sql === SUPABASE_PERMISSIONS_SQL_V3) {
        return Promise.reject(
          new Error('permission denied to change default privileges'),
        )
      }
      return Promise.resolve({ rows: [], rowCount: 0 })
    })
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.install({ supabase: true })).rejects.toThrow(
      /EQL v3 is installed.*NOT rolled back/s,
    )
    expect(mockQuery).toHaveBeenCalledWith('COMMIT')
    expect(mockQuery).not.toHaveBeenCalledWith('ROLLBACK')
  })
})

describe('Supabase grants split', () => {
  it('keeps SUPABASE_PERMISSIONS_SQL_V3 byte-identical to the pre-split block', async () => {
    const { SUPABASE_PERMISSIONS_SQL_V3 } = await import(
      '@/installer/grants.ts'
    )
    // The exact string the CLI shipped before the immediate/owner-scoped
    // split. `packages/stack-supabase/integration/grants.integration.test.ts`
    // live-proves this block, so it must not drift.
    expect(
      SUPABASE_PERMISSIONS_SQL_V3,
    ).toBe(`GRANT USAGE ON SCHEMA eql_v3 TO anon, authenticated, service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL ROUTINES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA eql_v3 TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT SELECT ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3 GRANT USAGE ON SEQUENCES TO anon, authenticated, service_role;
GRANT USAGE ON SCHEMA eql_v3_internal TO anon, authenticated, service_role;
GRANT EXECUTE ON ALL ROUTINES IN SCHEMA eql_v3_internal TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA eql_v3_internal GRANT EXECUTE ON ROUTINES TO anon, authenticated, service_role;
`)
  })

  it('splits every statement into exactly one half', async () => {
    const {
      SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
      SUPABASE_IMMEDIATE_GRANTS_SQL_V3,
      SUPABASE_PERMISSIONS_SQL_V3,
    } = await import('@/installer/grants.ts')
    const statements = (sql: string) =>
      sql.split('\n').filter((line) => line.trim() !== '')
    const combined = [
      ...statements(SUPABASE_IMMEDIATE_GRANTS_SQL_V3),
      ...statements(SUPABASE_DEFAULT_PRIVILEGES_SQL_V3),
    ].sort()
    expect(combined).toEqual(statements(SUPABASE_PERMISSIONS_SQL_V3).sort())
    for (const line of statements(SUPABASE_DEFAULT_PRIVILEGES_SQL_V3)) {
      expect(line).toMatch(/^ALTER DEFAULT PRIVILEGES FOR ROLE postgres /)
    }
    for (const line of statements(SUPABASE_IMMEDIATE_GRANTS_SQL_V3)) {
      expect(line).toMatch(/^GRANT /)
    }
  })

  it('guards every owner-scoped statement behind the membership check for migrations', async () => {
    const {
      SUPABASE_DEFAULT_PRIVILEGES_SQL_V3,
      SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3,
      SUPABASE_MIGRATION_GRANTS_SQL_V3,
      SUPABASE_IMMEDIATE_GRANTS_SQL_V3,
    } = await import('@/installer/grants.ts')
    // Every owner-scoped statement appears inside the DO block.
    for (const line of SUPABASE_DEFAULT_PRIVILEGES_SQL_V3.trim().split('\n')) {
      expect(SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3).toContain(line)
    }
    expect(SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3).toContain(
      "pg_has_role(current_user, 'postgres', 'MEMBER')",
    )
    expect(SUPABASE_GUARDED_DEFAULT_PRIVILEGES_SQL_V3).toContain(
      "EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres')",
    )
    // The migration block = immediate grants + guarded owner-scoped block,
    // with NO bare (unguarded) owner-scoped statement: every ALTER line must
    // be indented inside the DO body.
    expect(SUPABASE_MIGRATION_GRANTS_SQL_V3).toContain(
      SUPABASE_IMMEDIATE_GRANTS_SQL_V3,
    )
    for (const line of SUPABASE_MIGRATION_GRANTS_SQL_V3.split('\n')) {
      if (line.includes('ALTER DEFAULT PRIVILEGES')) {
        expect(line).toMatch(/^\s+ALTER DEFAULT PRIVILEGES/)
      }
    }
  })
})
