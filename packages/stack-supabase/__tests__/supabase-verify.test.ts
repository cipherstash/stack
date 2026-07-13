import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import type { IntrospectionResult } from '../src/introspect'
import { verifyDeclaredSchemas } from '../src/verify'

const introspection: IntrospectionResult = [
  {
    tableName: 'users',
    columns: [
      { columnName: 'id', domainName: null },
      { columnName: 'email', domainName: 'eql_v3_text_search' },
      { columnName: 'amount', domainName: 'eql_v3_integer_ord' },
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

// Two declared properties resolving to the same DB column pass verification —
// each checks out against the real column — and only blow up later, inside
// `EncryptedTable.build()`, with an error from the eql/v3 layer that names
// neither the colliding properties nor the `schemas` entry they came from.
describe('duplicate declared DB names', () => {
  it('throws naming the table and both colliding properties', () => {
    const users = encryptedTable('users', {
      a: types.TextSearch('email'),
      b: types.TextSearch('email'),
    })
    expect(() => verifyDeclaredSchemas({ users }, introspection)).toThrow(
      /users.*email.*"a".*"b"|users.*"a".*"b".*email/,
    )
  })

  it('allows two properties on different DB columns', () => {
    const users = encryptedTable('users', {
      a: types.TextSearch('email'),
      b: types.IntegerOrd('amount'),
    })
    expect(() => verifyDeclaredSchemas({ users }, introspection)).not.toThrow()
  })
})
