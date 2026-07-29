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

describe('EQLInstaller', () => {
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => vi.restoreAllMocks())

  it('reports sufficient permissions for a superuser', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({
      rows: [{ rolsuper: true, rolcreatedb: true }],
      rowCount: 1,
    })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.checkPermissions()).resolves.toEqual({
      ok: true,
      missing: [],
      isSuperuser: true,
    })
  })

  it('accepts database-local CREATE privilege for installing pgcrypto', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery
      .mockResolvedValueOnce({
        rows: [{ rolsuper: false, rolcreatedb: false }],
        rowCount: 1,
      })
      .mockResolvedValueOnce({ rows: [{ has_create: true }], rowCount: 1 })
      .mockResolvedValueOnce({ rows: [{ has_create: true }], rowCount: 1 })
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.checkPermissions()).resolves.toEqual({
      ok: true,
      missing: [],
      isSuperuser: false,
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

    await installer.install()

    const sqlCall = mockQuery.mock.calls.find(
      ([sql]) =>
        typeof sql === 'string' &&
        !['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql),
    )
    expect(sqlCall?.[0]).toContain('eql_v3')
    expect(sqlCall?.[0]).not.toContain('CREATE SCHEMA eql_v2')
    expect(mockQuery).toHaveBeenCalledWith('COMMIT')
  })

  it('grants both EQL v3 schemas to Supabase roles', async () => {
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
    mockEnd.mockResolvedValue(undefined)
    const { EQLInstaller, SUPABASE_PERMISSIONS_SQL_V3 } = await import(
      '@/installer/index.ts'
    )
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await installer.install({ supabase: true })

    expect(mockQuery).toHaveBeenCalledWith(SUPABASE_PERMISSIONS_SQL_V3)
    expect(SUPABASE_PERMISSIONS_SQL_V3).toContain('eql_v3_internal')
    expect(SUPABASE_PERMISSIONS_SQL_V3).not.toContain('eql_v2')
  })

  it('rolls back when the install SQL fails', async () => {
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

    await expect(installer.install()).rejects.toThrow('Failed to install EQL')
    expect(mockQuery).toHaveBeenCalledWith('ROLLBACK')
  })
})
