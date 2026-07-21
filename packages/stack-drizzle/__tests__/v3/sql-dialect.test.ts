import { not, sql } from 'drizzle-orm'
import { PgDialect } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { EQL_V3_FN_SCHEMA, v3Dialect } from '../../src/v3/sql-dialect'

const dialect = new PgDialect()
const render = (s: ReturnType<typeof sql>) => dialect.sqlToQuery(s).sql
const renderFull = (s: ReturnType<typeof sql>) => dialect.sqlToQuery(s)
const col = sql`"users"."x"`
const enc = sql`${'{"v":"t"}'}`

describe('v3Dialect', () => {
  it('equality via HMAC', () => {
    expect(render(v3Dialect.equality('eq', col, enc))).toBe(
      'eql_v3.eq("users"."x", $1)',
    )
  })

  it('inequality via HMAC', () => {
    expect(render(v3Dialect.equality('ne', col, enc))).toBe(
      'eql_v3.neq("users"."x", $1)',
    )
  })

  it('comparison via ORE', () => {
    expect(render(v3Dialect.comparison('gte', col, enc))).toBe(
      'eql_v3.gte("users"."x", $1)',
    )
  })

  it('range via ORE, parenthesised so it survives negation', () => {
    const lo = sql`${'{"v":"lo"}'}`
    const hi = sql`${'{"v":"hi"}'}`
    expect(render(v3Dialect.range(col, lo, hi))).toBe(
      '(eql_v3.gte("users"."x", $1) AND eql_v3.lte("users"."x", $2))',
    )
  })

  it('a negated range negates the whole conjunction, not just its first term', () => {
    const lo = sql`${'{"v":"lo"}'}`
    const hi = sql`${'{"v":"hi"}'}`

    // Drizzle's `not` renders `not ${condition}` with no parentheses of its
    // own. Postgres binds NOT tighter than AND, so an unparenthesised range
    // would silently become `(NOT gte) AND lte`.
    expect(render(not(v3Dialect.range(col, lo, hi)))).toBe(
      'not (eql_v3.gte("users"."x", $1) AND eql_v3.lte("users"."x", $2))',
    )
  })

  it('contains via two-arg function', () => {
    expect(render(v3Dialect.contains(col, enc))).toBe(
      'eql_v3.matches("users"."x", $1)',
    )
  })

  it('orderBy extracts the ord term', () => {
    expect(render(v3Dialect.orderBy(col))).toBe('eql_v3.ord_term("users"."x")')
  })

  it('selectorEntry uses the typed -> form required by functional indexes', () => {
    expect(render(v3Dialect.selectorEntry(col, sql`${'selector'}::text`))).toBe(
      '"users"."x" -> $1::text',
    )
  })

  // `render` above discards `.params`, so nothing here proved a value was BOUND
  // rather than concatenated into the SQL text. The only `sql.raw` in the
  // dialect interpolates constants (the schema + function name), so no
  // injectable path exists today — these pin that.
  describe('operand values are bound, never interpolated into SQL text', () => {
    const hostile = '{"v":"\\" OR 1=1 --","x":"$1","y":"back\\\\slash"}'

    it.each([
      ['equality', () => v3Dialect.equality('eq', col, sql`${hostile}`)],
      ['comparison', () => v3Dialect.comparison('gte', col, sql`${hostile}`)],
      ['contains', () => v3Dialect.contains(col, sql`${hostile}`)],
      [
        'selectorEntry',
        () => v3Dialect.selectorEntry(col, sql`${hostile}::text`),
      ],
      // `$1` in a title is consumed by vitest as an index into the case tuple,
      // so it cannot be used to name the SQL placeholder here.
    ])('%s binds a hostile operand as a positional parameter', (_name, build) => {
      const query = renderFull(build())

      expect(query.params).toEqual([hostile])
      expect(query.sql).toContain('$1')
      // The raw value must appear nowhere in the SQL text.
      expect(query.sql).not.toContain('OR 1=1')
      expect(query.sql).not.toContain('back\\slash')
    })

    it('range binds both bounds positionally, min first', () => {
      const query = renderFull(
        v3Dialect.range(col, sql`${'{"b":"min"}'}`, sql`${'{"b":"max"}'}`),
      )

      expect(query.params).toEqual(['{"b":"min"}', '{"b":"max"}'])
      expect(query.sql).toBe(
        '(eql_v3.gte("users"."x", $1) AND eql_v3.lte("users"."x", $2))',
      )
    })

    it('binds a large ciphertext without truncating or inlining it', () => {
      const big = `{"c":"${'z'.repeat(16384)}"}`
      const query = renderFull(v3Dialect.equality('eq', col, sql`${big}`))

      expect(query.params).toEqual([big])
      expect(query.sql).toBe('eql_v3.eq("users"."x", $1)')
    })
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
