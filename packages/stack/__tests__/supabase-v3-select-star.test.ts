import { describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { EncryptedQueryBuilderV3Impl } from '@/supabase/query-builder-v3'

/** Minimal Supabase double that records only the select string. */
function mockSupabase() {
  const selects: string[] = []
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
        data: [],
        error: null,
        count: null,
        status: 200,
        statusText: 'OK',
      }).then(onfulfilled, onrejected),
  }
  return { client: { from: () => qb }, selects }
}

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  amount: types.IntegerOrd('amount'),
  createdAt: types.TimestampOrd('created_at'),
})

// DB column names as introspection would report them (plaintext id/note included).
const ALL_COLUMNS = ['id', 'email', 'amount', 'created_at', 'note']

describe("v3 select('*') expansion", () => {
  it('expands * to the full column list and casts encrypted columns', async () => {
    const supabase = mockSupabase()
    const builder = new EncryptedQueryBuilderV3Impl(
      'users',
      users,
      {} as EncryptionClient,
      supabase.client,
      ALL_COLUMNS,
    )

    await builder.select('*')

    expect(supabase.selects[0]).toBe(
      'id, email::jsonb, amount::jsonb, created_at::jsonb, note',
    )
  })

  it('no-arg select() behaves exactly like select("*")', async () => {
    const supabase = mockSupabase()
    const builder = new EncryptedQueryBuilderV3Impl(
      'users',
      users,
      {} as EncryptionClient,
      supabase.client,
      ALL_COLUMNS,
    )

    await builder.select()

    expect(supabase.selects[0]).toBe(
      'id, email::jsonb, amount::jsonb, created_at::jsonb, note',
    )
  })

  it("still throws select('*') when no column list is available", async () => {
    const supabase = mockSupabase()
    const builder = new EncryptedQueryBuilderV3Impl(
      'users',
      users,
      {} as EncryptionClient,
      supabase.client,
      null,
    )

    expect(() => builder.select('*')).toThrow(/select\('\*'\)/)
    // v2 regression: a bare select() takes the same path and throws the same way.
    expect(() => builder.select()).toThrow(/select\('\*'\)/)
  })
})
