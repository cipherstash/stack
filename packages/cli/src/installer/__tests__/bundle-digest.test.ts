import { describe, expect, it, vi } from 'vitest'

/**
 * The CLI executes EQL SQL read off disk — from whatever `@cipherstash/eql`
 * resolved in the user's `node_modules`, since `tsup.config.ts` keeps the
 * package external precisely so the bundle is read at runtime. Nothing about
 * that read proves the bytes are the bundle the resolved release attests to.
 *
 * That is not hypothetical: a `3.0.5` tree in this repo carried an install
 * bundle hashing `7ad9c9f8…` while npm's published `3.0.5` hashed
 * `accde0030…`, because upstream restored the deprecated `ste_vec_contains`
 * aliases in the real release. `stash eql install` would have executed the
 * wrong one against a customer database and reported success — the whole
 * failure is silent. `packages/stack-prisma` already refuses on this same
 * digest (`readVerifiedInstallSql`); the CLI did not.
 */

// Lets a test substitute the bytes `readInstallSql()` returns without touching
// the real package files. `releaseManifest` and `installSqlPath` stay REAL, so
// the expected digest and the resolved path in the error message are the ones a
// user would actually see.
const eqlSql = vi.hoisted(() => ({ tampered: null as string | null }))
vi.mock('@cipherstash/eql/sql', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherstash/eql/sql')>()
  return {
    ...actual,
    readInstallSql: () => eqlSql.tampered ?? actual.readInstallSql(),
  }
})

// `install()` must refuse BEFORE it touches the database, so pg is stubbed and
// the call counts are the assertion.
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

const TAMPERED = '-- not the pinned bundle\nCREATE SCHEMA eql_v3;\n'

describe('bundled EQL SQL digest verification', () => {
  it('accepts the real pinned bundle (happy path)', async () => {
    eqlSql.tampered = null
    const { loadBundledEqlSql } = await import('@/installer/index.ts')
    const { releaseManifest } = await import('@cipherstash/eql/sql')
    const { createHash } = await import('node:crypto')

    const sql = loadBundledEqlSql()

    expect(createHash('sha256').update(sql).digest('hex')).toBe(
      releaseManifest.installSqlSha256,
    )
  })

  it('refuses SQL whose bytes do not hash to the manifest digest', async () => {
    eqlSql.tampered = TAMPERED
    const { loadBundledEqlSql } = await import('@/installer/index.ts')

    expect(() => loadBundledEqlSql()).toThrow(/digest verification/i)
    eqlSql.tampered = null
  })

  it('names the expected digest, the actual digest and the resolved path', async () => {
    eqlSql.tampered = TAMPERED
    const { loadBundledEqlSql } = await import('@/installer/index.ts')
    const { installSqlPath, releaseManifest } = await import(
      '@cipherstash/eql/sql'
    )
    const { createHash } = await import('node:crypto')
    const actualDigest = createHash('sha256').update(TAMPERED).digest('hex')

    let message = ''
    try {
      loadBundledEqlSql()
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    } finally {
      eqlSql.tampered = null
    }

    // The failure is currently silent; the message is the entire remedy.
    expect(message).toContain(releaseManifest.installSqlSha256)
    expect(message).toContain(actualDigest)
    expect(message).toContain(installSqlPath())
    expect(message).toContain(releaseManifest.eqlVersion)
  })

  it('refuses before executing anything against the database', async () => {
    vi.clearAllMocks()
    mockConnect.mockResolvedValue(undefined)
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
    mockEnd.mockResolvedValue(undefined)
    eqlSql.tampered = TAMPERED
    const { EQLInstaller } = await import('@/installer/index.ts')
    const installer = new EQLInstaller({ databaseUrl: 'postgres://test' })

    await expect(installer.install()).rejects.toThrow(/digest verification/i)
    // Not "rolled back after BEGIN" — nothing was sent at all.
    expect(mockQuery).not.toHaveBeenCalled()
    eqlSql.tampered = null
  })

  it('refuses to emit a migration carrying unverified SQL', async () => {
    eqlSql.tampered = TAMPERED
    const { buildEqlV3MigrationSql } = await import(
      '@/commands/eql/migration.ts'
    )

    expect(() => buildEqlV3MigrationSql({ supabase: false })).toThrow(
      /digest verification/i,
    )
    eqlSql.tampered = null
  })

  it('refuses to derive the expected verify surface from unverified SQL', async () => {
    eqlSql.tampered = TAMPERED
    const { bundledExpectedSurface } = await import('@/installer/verify.ts')

    expect(() => bundledExpectedSurface()).toThrow(/digest verification/i)
    eqlSql.tampered = null
  })
})
