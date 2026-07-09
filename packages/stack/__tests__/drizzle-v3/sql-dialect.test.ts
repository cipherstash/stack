import { not, sql } from 'drizzle-orm'
import { PgDialect } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { EQL_V3_FN_SCHEMA, v3Dialect } from '@/eql/v3/drizzle/sql-dialect'

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

  it('range via ORE, parenthesised so it survives negation', () => {
    const lo = sql`${'{"v":"lo"}'}`
    const hi = sql`${'{"v":"hi"}'}`
    expect(render(v3Dialect.range(col, lo, hi))).toBe(
      '(eql_v3.gte("users"."x", $1::jsonb) AND eql_v3.lte("users"."x", $2::jsonb))',
    )
  })

  it('a negated range negates the whole conjunction, not just its first term', () => {
    const lo = sql`${'{"v":"lo"}'}`
    const hi = sql`${'{"v":"hi"}'}`

    // Drizzle's `not` renders `not ${condition}` with no parentheses of its
    // own. Postgres binds NOT tighter than AND, so an unparenthesised range
    // would silently become `(NOT gte) AND lte`.
    expect(render(not(v3Dialect.range(col, lo, hi)))).toBe(
      'not (eql_v3.gte("users"."x", $1::jsonb) AND eql_v3.lte("users"."x", $2::jsonb))',
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

  it('every helper schema-qualifies its function call', () => {
    const lo = sql`${'{"v":"lo"}'}`
    const hi = sql`${'{"v":"hi"}'}`
    const fragments = [
      render(v3Dialect.equality('eq', col, enc)),
      render(v3Dialect.equality('ne', col, enc)),
      render(v3Dialect.comparison('gte', col, enc)),
      render(v3Dialect.contains(col, enc)),
      render(v3Dialect.orderBy(col)),
    ]

    // Deliberately asserts the LITERAL prefix, not `${EQL_V3_FN_SCHEMA}.`.
    // Deriving the expectation from the constant under test would hold for any
    // value of that constant — including a wrong one.
    for (const fragment of fragments) {
      expect(fragment.startsWith('eql_v3.')).toBe(true)
    }
    // `range` invokes two functions, neither of them leading the fragment.
    expect(
      (render(v3Dialect.range(col, lo, hi)).match(/eql_v3\./g) ?? []).length,
    ).toBe(2)
    // The constant is the single knob those literals must agree with, so a
    // one-line schema move fails here first and loudly.
    expect(EQL_V3_FN_SCHEMA).toBe('eql_v3')
  })
})
