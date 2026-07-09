import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import type { SupabaseClientLike } from '@/supabase'
import { encryptedSupabaseV3 } from '@/supabase'
import type { IntrospectionData } from '@/supabase/introspect'
import { EncryptedQueryBuilderV3Impl } from '@/supabase/query-builder-v3'

// --- Mocks -----------------------------------------------------------------
//
// `vi.mock` factories are hoisted above every import, so they cannot close over
// a plain top-level `const` (it would still be in its TDZ when the factory runs
// on first import). `vi.hoisted` lifts the spies alongside them.

const { introspectMock, encryptionMock, createClientMock } = vi.hoisted(() => ({
  introspectMock: vi.fn<(url: string) => Promise<unknown>>(),
  encryptionMock: vi.fn<(cfg: unknown) => Promise<unknown>>(),
  createClientMock: vi.fn(() => ({ from: () => ({}) })),
}))

vi.mock('@/supabase/introspect', async (importActual) => {
  const actual = await importActual<typeof import('@/supabase/introspect')>()
  return { ...actual, introspect: (url: string) => introspectMock(url) }
})

vi.mock('@/encryption', async (importActual) => {
  const actual = await importActual<typeof import('@/encryption')>()
  return { ...actual, Encryption: (cfg: unknown) => encryptionMock(cfg) }
})

vi.mock('@supabase/supabase-js', () => ({ createClient: createClientMock }))

const fakeClient = { from: () => ({}) } as unknown as SupabaseClientLike

function introspectionOf(data: Partial<IntrospectionData>): IntrospectionData {
  return { tables: data.tables ?? [], eqlDomains: data.eqlDomains ?? new Set() }
}

const usersIntrospection = introspectionOf({
  tables: [
    {
      tableName: 'users',
      columns: [
        { columnName: 'id', domainName: null },
        { columnName: 'email', domainName: 'text_search' },
      ],
    },
  ],
  eqlDomains: new Set(['text_search']),
})

beforeEach(() => {
  introspectMock.mockReset().mockResolvedValue(usersIntrospection)
  encryptionMock.mockReset().mockResolvedValue({})
  createClientMock.mockClear()
  delete process.env.DATABASE_URL
})
afterEach(() => vi.restoreAllMocks())

describe('encryptedSupabaseV3 factory', () => {
  it('url+key overload builds a client and introspects the given databaseUrl', async () => {
    await encryptedSupabaseV3('http://sb', 'anon-key', {
      databaseUrl: 'postgres://x',
    })
    expect(createClientMock).toHaveBeenCalledWith('http://sb', 'anon-key')
    expect(introspectMock).toHaveBeenCalledWith('postgres://x')
    expect(encryptionMock).toHaveBeenCalledTimes(1)
  })

  it('client overload uses the supplied client (no createClient)', async () => {
    await encryptedSupabaseV3(fakeClient, { databaseUrl: 'postgres://x' })
    expect(createClientMock).not.toHaveBeenCalled()
  })

  it('falls back to process.env.DATABASE_URL', async () => {
    process.env.DATABASE_URL = 'postgres://env'
    await encryptedSupabaseV3(fakeClient)
    expect(introspectMock).toHaveBeenCalledWith('postgres://env')
  })

  it('throws naming DATABASE_URL when no URL is available', async () => {
    await expect(encryptedSupabaseV3(fakeClient)).rejects.toThrow(
      /DATABASE_URL/,
    )
    expect(introspectMock).not.toHaveBeenCalled()
  })

  it('verifies BEFORE building the encryption client (wrong domain)', async () => {
    // email is text_search in the DB; declaring text_eq must fail...
    const users = encryptedTable('users', { email: types.TextEq('email') })
    await expect(
      encryptedSupabaseV3(fakeClient, {
        databaseUrl: 'postgres://x',
        schemas: { users },
      }),
    ).rejects.toThrow(/text_eq|text_search/)
    // ...and Encryption must never be reached.
    expect(encryptionMock).not.toHaveBeenCalled()
  })

  it('passes only non-empty tables to Encryption', async () => {
    introspectMock.mockResolvedValue(
      introspectionOf({
        tables: [
          {
            tableName: 'users',
            columns: [{ columnName: 'email', domainName: 'text_search' }],
          },
          {
            tableName: 'logs',
            columns: [{ columnName: 'line', domainName: null }],
          },
        ],
        eqlDomains: new Set(['text_search']),
      }),
    )
    await encryptedSupabaseV3(fakeClient, { databaseUrl: 'postgres://x' })
    const arg = encryptionMock.mock.calls[0][0] as { schemas: unknown[] }
    expect(arg.schemas).toHaveLength(1)
  })

  it('throws a diagnosis when no modelled EQL v3 columns exist anywhere', async () => {
    introspectMock.mockResolvedValue(
      introspectionOf({
        tables: [
          {
            tableName: 'logs',
            columns: [{ columnName: 'line', domainName: null }],
          },
        ],
      }),
    )
    await expect(
      encryptedSupabaseV3(fakeClient, { databaseUrl: 'postgres://x' }),
    ).rejects.toThrow(/no EQL v3 encrypted columns found/)
    expect(encryptionMock).not.toHaveBeenCalled()
  })

  it('throws from from() on an unknown table', async () => {
    const supabase = await encryptedSupabaseV3(fakeClient, {
      databaseUrl: 'postgres://x',
    })
    expect(() => supabase.from('nope')).toThrow(/unknown table/)
  })

  it('returns a v3 builder from from() on a known table', async () => {
    const supabase = await encryptedSupabaseV3(fakeClient, {
      databaseUrl: 'postgres://x',
    })
    expect(supabase.from('users')).toBeInstanceOf(EncryptedQueryBuilderV3Impl)
  })

  it('throws when a schemas record key ≠ its table name', async () => {
    const mislabelled = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    await expect(
      encryptedSupabaseV3(fakeClient, {
        databaseUrl: 'postgres://x',
        schemas: { orders: mislabelled },
      }),
    ).rejects.toThrow(/orders.*users|record key/)
  })

  it('throws on a recognized-but-unmodelled EQL domain', async () => {
    introspectMock.mockResolvedValue(
      introspectionOf({
        tables: [
          {
            tableName: 'metrics',
            columns: [{ columnName: 'score', domainName: 'integer_ord_ope' }],
          },
        ],
        eqlDomains: new Set(['integer_ord_ope']),
      }),
    )
    await expect(
      encryptedSupabaseV3(fakeClient, { databaseUrl: 'postgres://x' }),
    ).rejects.toThrow(/integer_ord_ope/)
    expect(encryptionMock).not.toHaveBeenCalled()
  })

  // `eqlVersion` is forced, not defaulted. A caller who passes `eqlVersion: 2`
  // against v3 domains would otherwise get a v2 encryption client and fail at
  // runtime with a 23514 CHECK violation, far from the cause.
  it('forces eqlVersion 3 over a caller-supplied config, passing other keys through', async () => {
    await encryptedSupabaseV3(fakeClient, {
      databaseUrl: 'postgres://x',
      config: { eqlVersion: 2, workspaceCrn: 'crn:test' } as never,
    })

    const arg = encryptionMock.mock.calls[0][0] as {
      config: Record<string, unknown>
    }
    expect(arg.config.eqlVersion).toBe(3)
    expect(arg.config.workspaceCrn).toBe('crn:test')
  })

  it('defaults config to { eqlVersion: 3 } when none is supplied', async () => {
    await encryptedSupabaseV3(fakeClient, { databaseUrl: 'postgres://x' })

    const arg = encryptionMock.mock.calls[0][0] as { config: unknown }
    expect(arg.config).toEqual({ eqlVersion: 3 })
  })
})
