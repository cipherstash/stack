import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SupabaseClientLike } from '../src/index.js'
import { encryptedSupabaseV3 } from '../src/index.js'
import type { IntrospectionData } from '../src/introspect'
import { EncryptedQueryBuilderV3Impl } from '../src/query-builder-v3'

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

vi.mock('../src/introspect', async (importActual) => {
  const actual = await importActual<typeof import('../src/introspect')>()
  return { ...actual, introspect: (url: string) => introspectMock(url) }
})

vi.mock('@cipherstash/stack/encryption', async (importActual) => {
  const actual =
    await importActual<typeof import('@cipherstash/stack/encryption')>()
  return { ...actual, Encryption: (cfg: unknown) => encryptionMock(cfg) }
})

vi.mock('@supabase/supabase-js', () => ({ createClient: createClientMock }))

const fakeClient = { from: () => ({}) } as unknown as SupabaseClientLike

function introspectionOf(data: Partial<IntrospectionData>): IntrospectionData {
  return {
    tables: data.tables ?? [],
    unmodelled: data.unmodelled ?? new Map(),
    eqlVersion: data.eqlVersion ?? null,
  }
}

const usersIntrospection = introspectionOf({
  tables: [
    {
      tableName: 'users',
      columns: [
        { columnName: 'id', domainName: null },
        { columnName: 'email', domainName: 'eql_v3_text_search' },
      ],
    },
  ],
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
            columns: [
              { columnName: 'email', domainName: 'eql_v3_text_search' },
            ],
          },
          {
            tableName: 'logs',
            columns: [{ columnName: 'line', domainName: null }],
          },
        ],
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

  it('threads the EQL 3.0.2 query-domain limitation into builders', async () => {
    introspectMock.mockResolvedValueOnce(
      introspectionOf({
        ...usersIntrospection,
        eqlVersion: '3.0.2',
      }),
    )
    const supabase = await encryptedSupabaseV3(fakeClient, {
      databaseUrl: 'postgres://x',
    })

    expect(() => supabase.from('users').matches('email', 'alice')).toThrow(
      /EQL 3\.0\.2\+/,
    )
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

  // An unmodelled EQL domain is a silent-leak hazard: the column stays in
  // `allColumns` so `select('*')` selects it, but it never enters the encrypt
  // config, so reads return raw ciphertext undecrypted. It MUST throw — but
  // only for the table the caller actually touches. Scanning the whole `public`
  // schema at construction bricks the adapter for every consumer of a database
  // that happens to contain one such column on an unrelated table.
  describe('unmodelled EQL domains', () => {
    // `users` is fully modelled. `metrics.score` is not. `metrics.label` is.
    const withUnmodelledMetrics = introspectionOf({
      tables: [
        {
          tableName: 'users',
          columns: [
            { columnName: 'id', domainName: null },
            { columnName: 'email', domainName: 'eql_v3_text_search' },
          ],
        },
        {
          tableName: 'metrics',
          columns: [
            { columnName: 'label', domainName: 'eql_v3_text_eq' },
            { columnName: 'score', domainName: 'eql_v3_integer_ord_ope' },
          ],
        },
      ],
      unmodelled: new Map([
        [
          'metrics',
          [{ columnName: 'score', domainName: 'eql_v3_integer_ord_ope' }],
        ],
      ]),
    })

    beforeEach(() => {
      introspectMock.mockResolvedValue(withUnmodelledMetrics)
    })

    it('constructs when the unmodelled column is on a table the caller never names', async () => {
      await expect(
        encryptedSupabaseV3(fakeClient, { databaseUrl: 'postgres://x' }),
      ).resolves.toBeDefined()
      expect(encryptionMock).toHaveBeenCalledTimes(1)
    })

    it('still serves a fully-modelled table from that same database', async () => {
      const es = await encryptedSupabaseV3(fakeClient, {
        databaseUrl: 'postgres://x',
      })
      expect(() => es.from('users')).not.toThrow()
    })

    it('throws from from() naming the table, column and domain', async () => {
      const es = await encryptedSupabaseV3(fakeClient, {
        databaseUrl: 'postgres://x',
      })
      expect(() => es.from('metrics')).toThrow(
        /metrics\.score.*integer_ord_ope/,
      )
    })

    // A declared table IS named by the caller, so it is validated eagerly —
    // preserving "fails at construction, not on the first query" exactly where
    // the caller asked for compile-time types.
    it('throws at construction when the unmodelled table is declared in schemas', async () => {
      const metrics = encryptedTable('metrics', {
        label: types.TextEq('label'),
      })
      await expect(
        encryptedSupabaseV3(fakeClient, {
          databaseUrl: 'postgres://x',
          schemas: { metrics },
        }),
      ).rejects.toThrow(/metrics\.score.*integer_ord_ope/)
      expect(encryptionMock).not.toHaveBeenCalled()
    })
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
