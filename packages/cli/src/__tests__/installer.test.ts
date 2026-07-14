import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mockConnect = vi.fn()
const mockQuery = vi.fn()
const mockEnd = vi.fn()

vi.mock('pg', () => {
  const Client = vi.fn(() => ({
    connect: mockConnect,
    query: mockQuery,
    end: mockEnd,
  }))
  return { default: { Client } }
})

describe('EQLInstaller', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('checkPermissions', () => {
    it('returns ok when role is superuser', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({
        rows: [{ rolsuper: true, rolcreatedb: true }],
        rowCount: 1,
      })
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      const result = await installer.checkPermissions()
      expect(result.ok).toBe(true)
      expect(result.missing).toEqual([])
    })

    it('returns missing permissions when role lacks privileges', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockEnd.mockResolvedValue(undefined)

      let queryCall = 0
      mockQuery.mockImplementation(() => {
        queryCall++
        switch (queryCall) {
          // pg_roles query — not superuser
          case 1:
            return {
              rows: [{ rolsuper: false, rolcreatedb: false }],
              rowCount: 1,
            }
          // has_database_privilege — no CREATE
          case 2:
            return { rows: [{ has_create: false }], rowCount: 1 }
          // has_schema_privilege — no CREATE on public
          case 3:
            return { rows: [{ has_create: false }], rowCount: 1 }
          // pgcrypto check — not installed
          case 4:
            return { rows: [], rowCount: 0 }
          default:
            return { rows: [], rowCount: 0 }
        }
      })

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      const result = await installer.checkPermissions()
      expect(result.ok).toBe(false)
      expect(result.missing).toHaveLength(3)
    })
  })

  describe('isInstalled', () => {
    it('returns false when schema does not exist', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      const result = await installer.isInstalled()
      expect(result).toBe(false)
    })

    it('returns true when schema exists', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({
        rows: [{ found: 1 }],
        rowCount: 1,
      })
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      const result = await installer.isInstalled({ eqlVersion: 2 })
      expect(result).toBe(true)
      expect(mockQuery).toHaveBeenCalledWith(expect.any(String), [['eql_v2']])
    })
  })

  describe('install', () => {
    it('uses bundled SQL and executes in a transaction', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
      mockEnd.mockResolvedValue(undefined)

      const fetchSpy = vi.spyOn(globalThis, 'fetch')

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await installer.install({ eqlVersion: 2 })

      // Should NOT call fetch — uses bundled SQL
      expect(fetchSpy).not.toHaveBeenCalled()
      expect(mockQuery).toHaveBeenCalledWith('BEGIN')
      // The second query should be the bundled SQL (a large string)
      const sqlCall = mockQuery.mock.calls.find(
        (call: string[]) =>
          typeof call[0] === 'string' &&
          call[0] !== 'BEGIN' &&
          call[0] !== 'COMMIT',
      )
      expect(sqlCall).toBeDefined()
      expect(sqlCall[0]).toContain('eql_v2')
      expect(mockQuery).toHaveBeenCalledWith('COMMIT')
    })

    it('fetches from GitHub when latest: true', async () => {
      const installSql = 'CREATE SCHEMA eql_v2;'

      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
      mockEnd.mockResolvedValue(undefined)

      const fetchSpy = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValue(new Response(installSql, { status: 200 }))

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await installer.install({ eqlVersion: 2, latest: true })

      expect(fetchSpy).toHaveBeenCalledWith(
        expect.stringContaining('cipherstash-encrypt.sql'),
      )
      expect(mockQuery).toHaveBeenCalledWith('BEGIN')
      expect(mockQuery).toHaveBeenCalledWith(installSql)
      expect(mockQuery).toHaveBeenCalledWith('COMMIT')
    })

    it('grants Supabase permissions as a single SUPABASE_PERMISSIONS_SQL query', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller, SUPABASE_PERMISSIONS_SQL } = await import(
        '@/installer/index.ts'
      )
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await installer.install({ eqlVersion: 2, supabase: true })

      // Capture every query string that isn't a transaction control verb.
      const otherCalls = mockQuery.mock.calls
        .map((call: unknown[]) => call[0])
        .filter(
          (sql: unknown): sql is string =>
            typeof sql === 'string' &&
            sql !== 'BEGIN' &&
            sql !== 'COMMIT' &&
            sql !== 'ROLLBACK',
        )

      // Two non-transaction queries: bundled EQL SQL, then permissions SQL.
      expect(otherCalls).toHaveLength(2)
      expect(otherCalls[1]).toBe(SUPABASE_PERMISSIONS_SQL)
      // Permissions SQL must mention each role + the eql_v2 schema.
      expect(SUPABASE_PERMISSIONS_SQL).toContain('eql_v2')
      expect(SUPABASE_PERMISSIONS_SQL).toContain('anon')
      expect(SUPABASE_PERMISSIONS_SQL).toContain('authenticated')
      expect(SUPABASE_PERMISSIONS_SQL).toContain('service_role')
    })

    it('installs the v3 bundle and grants eql_v3 permissions with eqlVersion: 3 + supabase', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller, SUPABASE_PERMISSIONS_SQL_V3 } = await import(
        '@/installer/index.ts'
      )
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await installer.install({ eqlVersion: 3, supabase: true })

      const otherCalls = mockQuery.mock.calls
        .map((call: unknown[]) => call[0])
        .filter(
          (sql: unknown): sql is string =>
            typeof sql === 'string' &&
            sql !== 'BEGIN' &&
            sql !== 'COMMIT' &&
            sql !== 'ROLLBACK',
        )

      expect(otherCalls).toHaveLength(2)
      // Since eql-3.0.0 there is ONE v3 bundle for every target: the
      // operator-class statements run inside a DO block that self-skips on
      // insufficient_privilege, and the bundle disables the ORE-backed
      // domains when the opclass is absent (CIP-3468). The supabase install
      // therefore executes the SAME artifact as the direct install.
      expect(otherCalls[0]).toContain('eql_v3')
      expect(otherCalls[0]).toContain('CREATE OPERATOR CLASS')
      expect(otherCalls[0]).toContain('insufficient_privilege')
      // The grants are keyed to eql_v3, not eql_v2. The installed block must be
      // the SAME string the Supabase migration file embeds — the installer used
      // to rebuild it from the schema name alone, letting the two drift.
      expect(otherCalls[1]).toBe(SUPABASE_PERMISSIONS_SQL_V3)
      expect(SUPABASE_PERMISSIONS_SQL_V3).toContain('eql_v3')
      expect(SUPABASE_PERMISSIONS_SQL_V3).not.toContain('eql_v2')

      // `eql_v3.eq_term`/`ord_term`/`match_term` are SECURITY INVOKER and
      // qualify `eql_v3_internal.*` in their bodies, so without USAGE on that
      // schema every encrypted filter fails for anon/authenticated with
      // "permission denied for schema eql_v3_internal". See
      // `supabaseInternalPermissionsSql`, and the live proof in
      // packages/stack/__tests__/supabase-v3-grants-pg.test.ts.
      expect(SUPABASE_PERMISSIONS_SQL_V3).toContain(
        'GRANT USAGE ON SCHEMA eql_v3_internal TO anon, authenticated, service_role;',
      )
      expect(SUPABASE_PERMISSIONS_SQL_V3).toContain(
        'GRANT EXECUTE ON ALL ROUTINES IN SCHEMA eql_v3_internal TO anon, authenticated, service_role;',
      )
    })

    // `eql_v2` has no internal schema; the v3-only addition must not leak into
    // the v2 block, where it would fail with "schema does not exist".
    it('does not grant an internal schema in the v2 permissions block', async () => {
      const { SUPABASE_PERMISSIONS_SQL } = await import('@/installer/index.ts')

      expect(SUPABASE_PERMISSIONS_SQL).not.toContain('_internal')
    })

    it('installs the full v3 bundle (with operator classes) without supabase', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await installer.install({ eqlVersion: 3 })

      const sqlCall = mockQuery.mock.calls.find(
        (call: string[]) =>
          typeof call[0] === 'string' &&
          call[0] !== 'BEGIN' &&
          call[0] !== 'COMMIT',
      )
      expect(sqlCall).toBeDefined()
      expect(sqlCall?.[0]).toContain('eql_v3')
      expect(sqlCall?.[0]).toContain('CREATE OPERATOR CLASS')
    })

    it('rejects latest: true for eqlVersion: 3', async () => {
      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await expect(
        installer.install({ eqlVersion: 3, latest: true }),
      ).rejects.toThrow('not supported for EQL v3')
    })

    it('requires BOTH eql_v3 and eql_v3_internal for isInstalled({ eqlVersion: 3 })', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      // Current-generation install: both schemas present
      mockQuery.mockResolvedValue({ rows: [{ found: 2 }], rowCount: 1 })
      await expect(installer.isInstalled({ eqlVersion: 3 })).resolves.toBe(true)
      expect(mockQuery).toHaveBeenCalledWith(expect.any(String), [
        ['eql_v3', 'eql_v3_internal'],
      ])

      // STALE pre-alpha.2 install: eql_v3 exists but eql_v3_internal does not
      // — must report NOT installed so an install run replaces it instead of
      // a stale surface silently accepting wrong-generation wire data.
      mockQuery.mockResolvedValue({ rows: [{ found: 1 }], rowCount: 1 })
      await expect(installer.isInstalled({ eqlVersion: 3 })).resolves.toBe(
        false,
      )
    })

    it('grants eql_v3 AND eql_v3_internal for the v3 supabase install', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
      mockEnd.mockResolvedValue(undefined)

      const { EQLInstaller, SUPABASE_PERMISSIONS_SQL_V3 } = await import(
        '@/installer/index.ts'
      )
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await installer.install({ eqlVersion: 3, supabase: true })

      const otherCalls = mockQuery.mock.calls
        .map((call: unknown[]) => call[0])
        .filter(
          (sql: unknown): sql is string =>
            typeof sql === 'string' &&
            sql !== 'BEGIN' &&
            sql !== 'COMMIT' &&
            sql !== 'ROLLBACK',
        )
      expect(otherCalls[1]).toBe(SUPABASE_PERMISSIONS_SQL_V3)
      // The eql_v3 operators call SECURITY INVOKER functions that live in
      // eql_v3_internal — the roles need grants on BOTH schemas.
      expect(SUPABASE_PERMISSIONS_SQL_V3).toContain(
        'GRANT USAGE ON SCHEMA eql_v3 ',
      )
      expect(SUPABASE_PERMISSIONS_SQL_V3).toContain(
        'GRANT USAGE ON SCHEMA eql_v3_internal ',
      )
    })

    it('rolls back on SQL execution failure', async () => {
      mockConnect.mockResolvedValue(undefined)
      mockEnd.mockResolvedValue(undefined)

      mockQuery.mockImplementation((sql: string) => {
        // BEGIN succeeds, any SQL containing eql_v2 (the bundled install) fails
        if (sql !== 'BEGIN' && sql !== 'COMMIT' && sql !== 'ROLLBACK') {
          return Promise.reject(new Error('permission denied'))
        }
        return Promise.resolve({ rows: [], rowCount: 0 })
      })

      const { EQLInstaller } = await import('@/installer/index.ts')
      const installer = new EQLInstaller({
        databaseUrl: 'postgresql://localhost:5432/test',
      })

      await expect(installer.install()).rejects.toThrow('Failed to install EQL')
      expect(mockQuery).toHaveBeenCalledWith('ROLLBACK')
    })
  })
})
