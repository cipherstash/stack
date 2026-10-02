import { describe, expect, it } from 'vitest'
import { qualifyTable } from '../cursor.js'
import { quoteIdent } from '../sql.js'

describe('quoteIdent', () => {
  it('wraps simple identifiers in double quotes', () => {
    expect(quoteIdent('email')).toBe('"email"')
  })

  it('escapes embedded double quotes', () => {
    expect(quoteIdent('foo"bar')).toBe('"foo""bar"')
  })
})

describe('qualifyTable', () => {
  it('quotes a single-part table name', () => {
    expect(qualifyTable('users')).toBe('"users"')
  })

  it('quotes each part of a schema-qualified name', () => {
    expect(qualifyTable('public.users')).toBe('"public"."users"')
  })
})
