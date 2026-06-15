import { sql } from 'drizzle-orm'
import { PgDialect } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { v2Dialect, v3Dialect } from '../../src/pg/sql-dialect'

const render = (s: ReturnType<typeof sql>) => new PgDialect().sqlToQuery(s).sql

describe('v2Dialect', () => {
  it('comparison(gt) emits eql_v2.gt(...)', () => {
    const out = v2Dialect.comparison('gt', sql`"col"`, sql`'enc'`)
    expect(render(out)).toContain('eql_v2.gt(')
  })

  it('range emits eql_v2.gte AND eql_v2.lte', () => {
    const out = v2Dialect.range(sql`"col"`, sql`'lo'`, sql`'hi'`)
    const rendered = render(out)
    expect(rendered).toContain('eql_v2.gte(')
    expect(rendered).toContain('eql_v2.lte(')
  })

  it('match(like) emits eql_v2.like(...)', () => {
    const out = v2Dialect.match('like', sql`"col"`, sql`'enc'`)
    expect(render(out)).toContain('eql_v2.like(')
  })

  it('orderBy emits eql_v2.order_by(...)', () => {
    const out = v2Dialect.orderBy(sql`"col"`)
    expect(render(out)).toContain('eql_v2.order_by(')
  })
})

describe('v3Dialect', () => {
  // Reconciled against the real eql_v3 SQL (EQL 035952e): v3 compares EXTRACTED
  // index terms — eq_term/ord_term/match_term on the column, and the jsonb helper
  // extractors hmac_256/ore_block_u64_8_256/bloom_filter on the search term — so the
  // search term is never coerced into a domain whose CHECK requires ciphertext.
  it('equality(eq) compares eq_term to hmac_256 of the jsonb term', () => {
    const rendered = render(v3Dialect.equality('eq', sql`"col"`, sql`'enc'`))
    expect(rendered).toContain('eql_v3.eq_term(')
    expect(rendered).toContain('=')
    expect(rendered).toContain('eql_v3.hmac_256(')
    expect(rendered).toContain('::jsonb')
  })

  it('equality(ne) emits <> between eq_term and hmac_256', () => {
    const rendered = render(v3Dialect.equality('ne', sql`"col"`, sql`'enc'`))
    expect(rendered).toContain('eql_v3.eq_term(')
    expect(rendered).toContain('<>')
    expect(rendered).toContain('eql_v3.hmac_256(')
  })

  // All four comparison ops, not just lt: guards ORD_SYMBOL against a copy-paste
  // (e.g. gte→'>'). The exact symbol must sit between the two extractor calls —
  // `) <sym> eql_v3.ore_block_u64_8_256(` — which disambiguates `>` from `>=`.
  it.each([
    ['gt', '>'],
    ['gte', '>='],
    ['lt', '<'],
    ['lte', '<='],
  ] as const)(
    'comparison(%s) emits ord_term %s ore_block_u64_8_256 of the term',
    (op, symbol) => {
      const rendered = render(v3Dialect.comparison(op, sql`"col"`, sql`'enc'`))
      expect(rendered).toContain('eql_v3.ord_term(')
      expect(rendered).toContain('eql_v3.ore_block_u64_8_256(')
      expect(rendered).toContain(`) ${symbol} eql_v3.ore_block_u64_8_256(`)
      expect(rendered).not.toContain('eql_v3.lt(')
    },
  )

  it('range emits ord_term >= … AND ord_term <= … over ore blocks', () => {
    const rendered = render(v3Dialect.range(sql`"col"`, sql`'lo'`, sql`'hi'`))
    expect(rendered).toContain('eql_v3.ord_term(')
    expect(rendered).toContain('>=')
    expect(rendered).toContain('<=')
    expect(rendered).toContain('eql_v3.ore_block_u64_8_256(')
  })

  it('match emits match_term @> bloom_filter of the jsonb term', () => {
    const rendered = render(v3Dialect.match('like', sql`"col"`, sql`'enc'`))
    expect(rendered).toContain('eql_v3.match_term(')
    expect(rendered).toContain('@>')
    expect(rendered).toContain('eql_v3.bloom_filter(')
  })

  it('orderBy emits eql_v3.ord_term(...)', () => {
    expect(render(v3Dialect.orderBy(sql`"col"`))).toContain('eql_v3.ord_term(')
  })
})
