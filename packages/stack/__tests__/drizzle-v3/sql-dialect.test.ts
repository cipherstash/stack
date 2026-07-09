import { sql } from 'drizzle-orm'
import { PgDialect } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { v3Dialect } from '@/eql/v3/drizzle/sql-dialect'

const dialect = new PgDialect()
const render = (s: ReturnType<typeof sql>) => dialect.sqlToQuery(s).sql
const col = sql`"users"."x"`
const enc = sql`${'{"v":"t"}'}`

describe('v3Dialect', () => {
  it('equality via HMAC', () => {
    expect(render(v3Dialect.equality('eq', col, enc))).toBe(
      'eql_v3.eq("users"."x", $1::jsonb)',
    )
  })

  it('inequality via HMAC', () => {
    expect(render(v3Dialect.equality('ne', col, enc))).toBe(
      'eql_v3.neq("users"."x", $1::jsonb)',
    )
  })

  it('comparison via ORE', () => {
    expect(render(v3Dialect.comparison('gte', col, enc))).toBe(
      'eql_v3.gte("users"."x", $1::jsonb)',
    )
  })

  it('range via ORE', () => {
    const lo = sql`${'{"v":"lo"}'}`
    const hi = sql`${'{"v":"hi"}'}`
    expect(render(v3Dialect.range(col, lo, hi))).toBe(
      'eql_v3.gte("users"."x", $1::jsonb) AND eql_v3.lte("users"."x", $2::jsonb)',
    )
  })

  it('contains via two-arg function', () => {
    expect(render(v3Dialect.contains(col, enc))).toBe(
      'eql_v3.contains("users"."x", $1::jsonb)',
    )
  })

  it('orderBy extracts the ord term', () => {
    expect(render(v3Dialect.orderBy(col))).toBe('eql_v3.ord_term("users"."x")')
  })
})
