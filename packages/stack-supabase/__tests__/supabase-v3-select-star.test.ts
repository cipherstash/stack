import { describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { EncryptedQueryBuilderV3Impl } from '../src/query-builder-v3'

/**
 * Supabase double that records the select string AND simulates the part of
 * PostgREST this adapter depends on: a `alias:column::jsonb` token returns the
 * value under `alias`, a bare `column::jsonb` (or `column`) under `column`.
 *
 * Simulating the rename is the point. The alias is the ONLY thing that makes a
 * renamed column come back under its JS property name, and it is produced
 * server-side — a double that echoes rows verbatim would assert nothing about
 * it. `dbRows` are keyed by DB column name, exactly as Postgres stores them.
 */
function mockSupabase(dbRows: Record<string, unknown>[] = []) {
  const selects: string[] = []

  const project = (select: string) =>
    dbRows.map((dbRow) => {
      const row: Record<string, unknown> = {}
      for (const token of select.split(',')) {
        const bare = token.trim().replace(/::jsonb$/, '')
        const [alias, column] = bare.includes(':')
          ? bare.split(':')
          : [bare, bare]
        row[alias] = dbRow[column]
      }
      return row
    })

  // biome-ignore lint/suspicious/noExplicitAny: test double
  const qb: any = {
    select: (s: string) => {
      selects.push(s)
      return qb
    },
    then: (
      onfulfilled?: ((v: unknown) => unknown) | null,
      onrejected?: ((r: unknown) => unknown) | null,
    ) =>
      Promise.resolve({
        data: project(selects[0] ?? ''),
        error: null,
        count: null,
        status: 200,
        statusText: 'OK',
      }).then(onfulfilled, onrejected),
  }
  return { client: { from: () => qb }, selects }
}

/** Identity decrypt — this suite is about column naming, not envelopes. */
function mockEncryptionClient() {
  const operation = <T>(data: T) => ({
    withLockContext: () => operation(data),
    audit: () => operation(data),
    then: (f?: ((v: { data: T }) => unknown) | null) =>
      Promise.resolve({ data }).then(f),
  })
  return {
    decryptModel: (m: Record<string, unknown>) => operation(m),
    bulkDecryptModels: (m: Record<string, unknown>[]) => operation(m),
  } as unknown as EncryptionClient
}

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  amount: types.IntegerOrd('amount'),
  createdAt: types.TimestampOrd('created_at'),
})

// DB column names as introspection would report them (plaintext id/note included).
const ALL_COLUMNS = ['id', 'email', 'amount', 'created_at', 'note']

function builderFor(
  supabase: ReturnType<typeof mockSupabase>,
  allColumns: string[] | null = ALL_COLUMNS,
) {
  return new EncryptedQueryBuilderV3Impl(
    'users',
    users,
    mockEncryptionClient(),
    supabase.client,
    allColumns,
  )
}

describe("v3 select('*') expansion", () => {
  it('expands * to the full column list and casts encrypted columns', async () => {
    const supabase = mockSupabase()
    await builderFor(supabase).select('*')

    // `created_at` is aliased back to its JS property name; `id`/`note` are
    // plaintext passthrough and `email`/`amount` are named identically in both.
    expect(supabase.selects[0]).toBe(
      'id, email::jsonb, amount::jsonb, createdAt:created_at::jsonb, note',
    )
  })

  it('no-arg select() behaves exactly like select("*")', async () => {
    const supabase = mockSupabase()
    await builderFor(supabase).select()

    expect(supabase.selects[0]).toBe(
      'id, email::jsonb, amount::jsonb, createdAt:created_at::jsonb, note',
    )
  })

  it("still throws select('*') when no column list is available", async () => {
    const supabase = mockSupabase()
    const builder = builderFor(supabase, null)

    expect(() => builder.select('*')).toThrow(/select\('\*'\)/)
    // v2 regression: a bare select() takes the same path and throws the same way.
    expect(() => builder.select()).toThrow(/select\('\*'\)/)
  })

  it("throws select('*') for an empty column list, not an empty select", async () => {
    // The guard is `=== null || .length === 0`. Only the null arm has a caller
    // today (`index.ts` passes `?? null`), so nothing stops a future `?? []`
    // from turning an unusable `*` into a silent zero-column select.
    const supabase = mockSupabase()
    const builder = builderFor(supabase, [])

    expect(() => builder.select('*')).toThrow(/select\('\*'\)/)
    expect(() => builder.select()).toThrow(/select\('\*'\)/)
  })
})

describe("REGRESSION: select('*') keys rows by JS property, not DB column", () => {
  // A declared column whose property name differs from its DB column is the
  // only case that can drift: synthesized columns always have property == DB
  // name. Before the `expandAllColumns` override, `select('*')` emitted the
  // unaliased `created_at::jsonb`, so rows came back keyed `created_at` while
  // the declared row type promises `createdAt` — `row.createdAt` was silently
  // `undefined` for a field TypeScript guaranteed as a Date.
  const dbRow = {
    id: 1,
    email: 'a@b.com',
    amount: 30,
    created_at: '2026-01-02T03:04:05.000Z',
    note: 'hi',
  }

  it('returns the renamed column under its property name', async () => {
    const supabase = mockSupabase([dbRow])
    const { data } = await builderFor(supabase).select('*')

    expect(data![0].createdAt).toBeInstanceOf(Date)
    expect((data![0].createdAt as Date).toISOString()).toBe(
      '2026-01-02T03:04:05.000Z',
    )
    expect(data![0]).not.toHaveProperty('created_at')
  })

  it("select('*') and an explicit property select agree on row shape", async () => {
    const star = mockSupabase([dbRow])
    const explicit = mockSupabase([dbRow])

    const { data: starData } = await builderFor(star).select('*')
    const { data: explicitData } = await builderFor(explicit).select(
      'id, email, amount, createdAt, note',
    )

    expect(Object.keys(starData![0]).sort()).toEqual(
      Object.keys(explicitData![0]).sort(),
    )
    expect(starData![0]).toEqual(explicitData![0])
  })

  it('leaves plaintext passthrough columns under their DB name', async () => {
    const supabase = mockSupabase([dbRow])
    const { data } = await builderFor(supabase).select('*')

    expect(data![0].id).toBe(1)
    expect(data![0].note).toBe('hi')
  })

  it('does not treat a DB column named like an Object.prototype member as a property', async () => {
    // `dbToProp['constructor']` would resolve to Object.prototype.constructor on
    // a plain object, emitting a function where a column name belongs.
    const supabase = mockSupabase()
    const builder = new EncryptedQueryBuilderV3Impl(
      'weird',
      encryptedTable('weird', { email: types.TextSearch('email') }),
      mockEncryptionClient(),
      supabase.client,
      ['constructor', 'toString', 'email'],
    )
    await builder.select('*')

    expect(supabase.selects[0]).toBe('constructor, toString, email::jsonb')
  })
})
