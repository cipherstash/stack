import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import type { IntrospectionResult } from '@/supabase/introspect'
import { verifyDeclaredSchemas } from '@/supabase/verify'

const introspection: IntrospectionResult = [
  {
    tableName: 'users',
    columns: [
      { columnName: 'id', domainName: null },
      { columnName: 'email', domainName: 'text_search' },
      { columnName: 'amount', domainName: 'integer_ord' },
    ],
  },
]

describe('verifyDeclaredSchemas', () => {
  it('passes when every declared column matches its introspected domain', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
      amount: types.IntegerOrd('amount'),
    })
    expect(() => verifyDeclaredSchemas({ users }, introspection)).not.toThrow()
  })

  it('passes when only a subset of encrypted columns is declared', () => {
    const users = encryptedTable('users', { email: types.TextSearch('email') })
    expect(() => verifyDeclaredSchemas({ users }, introspection)).not.toThrow()
  })

  it('throws naming the table when a declared table is absent', () => {
    const orders = encryptedTable('orders', {
      total: types.IntegerOrd('total'),
    })
    expect(() => verifyDeclaredSchemas({ orders }, introspection)).toThrow(
      /table "orders"/,
    )
  })

  it('throws naming the column when a declared column is absent', () => {
    const users = encryptedTable('users', { missing: types.TextEq('missing') })
    expect(() => verifyDeclaredSchemas({ users }, introspection)).toThrow(
      /users\.missing/,
    )
  })

  it('throws naming both domains when the domain differs', () => {
    // email is actually text_search; declaring text_eq must fail at startup.
    const users = encryptedTable('users', { email: types.TextEq('email') })
    expect(() => verifyDeclaredSchemas({ users }, introspection)).toThrow(
      /text_eq.*text_search|text_search.*text_eq/,
    )
  })

  // The `actual ?? '(none)'` arm: `id` exists but carries no domain. Declaring
  // it encrypted must fail at construction, not as a 23514 CHECK violation on
  // the first insert.
  it('throws "(none)" when a declared column is plaintext in the database', () => {
    const users = encryptedTable('users', { id: types.IntegerEq('id') })
    expect(() => verifyDeclaredSchemas({ users }, introspection)).toThrow(
      /users\.id.*\(none\).*integer_eq/,
    )
  })
})
