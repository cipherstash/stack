import { and } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { eqlV3Type } from '../../src/pg/v3/eql-v3-type'
import { setupV3 } from '../test-utils'

const table = pgTable('v3_ops', {
  t_eq: eqlV3Type<string>('t_eq', { dataType: 'text', index: 'equality' }),
  t_ord: eqlV3Type<string>('t_ord', {
    dataType: 'text',
    index: 'orderAndRange',
  }),
  t_match: eqlV3Type<string>('t_match', {
    dataType: 'text',
    index: 'freeTextSearch',
  }),
})

// Plain (non-encrypted) columns — exercise the native fallback branches.
const plainTable = pgTable('plain_ops', {
  age: integer('age'),
  name: text('name'),
})

describe('v3 operators encrypt params (not plaintext)', () => {
  it('eq on text_eq compares eq_term to hmac_256 with an encrypted param', async () => {
    const { protectOps, dialect, encryptQuery } = setupV3()
    const condition = await protectOps.eq(table.t_eq, 'alice')
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('eql_v3.eq_term(')
    expect(query.sql).toContain('eql_v3.hmac_256(')
    expect(query.params[0]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
  })

  it('lt on text_ord compares ord_term to ore_block with an encrypted param', async () => {
    const { protectOps, dialect } = setupV3()
    const condition = await protectOps.lt(table.t_ord, 'm')
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('eql_v3.ord_term(')
    expect(query.sql).toContain('<')
    expect(query.sql).toContain('eql_v3.ore_block_u64_8_256(')
    expect(query.params[0]).toContain('encrypted-value')
  })

  it('ilike on text_match emits match_term @> bloom_filter with an encrypted param', async () => {
    const { protectOps, dialect } = setupV3()
    const condition = await protectOps.ilike(table.t_match, 'aard')
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('eql_v3.match_term(')
    expect(query.sql).toContain('@>')
    expect(query.sql).toContain('eql_v3.bloom_filter(')
    expect(query.params[0]).toContain('encrypted-value')
  })

  // All four ordering ops at the operator level (not just lt): confirms each routes
  // through dialect.comparison with the right symbol and an encrypted param.
  it.each([
    ['gt', '>'],
    ['gte', '>='],
    ['lt', '<'],
    ['lte', '<='],
  ] as const)(
    '%s on text_ord emits ord_term %s ore_block with an encrypted param',
    async (op, symbol) => {
      const { protectOps, dialect } = setupV3()
      const condition = await protectOps[op](table.t_ord, 'm')
      const query = dialect.sqlToQuery(condition)
      expect(query.sql).toContain('eql_v3.ord_term(')
      expect(query.sql).toContain(`) ${symbol} eql_v3.ore_block_u64_8_256(`)
      expect(query.params[0]).toContain('encrypted-value')
    },
  )

  it('between on text_ord emits ord_term >= … AND ord_term <= … with two encrypted params', async () => {
    const { protectOps, dialect } = setupV3()
    const condition = await protectOps.between(table.t_ord, 'a', 'z')
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('eql_v3.ord_term(')
    expect(query.sql).toContain('>=')
    expect(query.sql).toContain('<=')
    expect(query.sql).toContain('eql_v3.ore_block_u64_8_256(')
    expect(query.sql).not.toContain('NOT (')
    expect(query.params).toHaveLength(2)
    expect(query.params[0]).toContain('encrypted-value')
    expect(query.params[1]).toContain('encrypted-value')
  })

  it('notBetween on text_ord wraps the range in NOT (...) with two encrypted params', async () => {
    const { protectOps, dialect } = setupV3()
    const condition = await protectOps.notBetween(table.t_ord, 'a', 'z')
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('NOT (')
    expect(query.sql).toContain('eql_v3.ord_term(')
    expect(query.sql).toContain('eql_v3.ore_block_u64_8_256(')
    expect(query.params).toHaveLength(2)
  })
})

describe('v3 set membership routes through the dialect seam', () => {
  it('inArray on text_eq emits eq_term/hmac_256 per value (not native =), OR-combined', async () => {
    const { protectOps, dialect, encryptQuery } = setupV3()
    const condition = await protectOps.inArray(table.t_eq, ['alice', 'bob'])
    const query = dialect.sqlToQuery(condition)
    // Must go through the v3 seam, not Drizzle's bare `eq` (native `=`), which would
    // coerce the term into text_eq and fail the domain CHECK (SQLSTATE 23514).
    expect(query.sql).toContain('eql_v3.eq_term(')
    expect(query.sql).toContain('eql_v3.hmac_256(')
    expect(query.sql.toLowerCase()).toContain(' or ')
    expect(query.params).toHaveLength(2)
    expect(query.params[0]).toContain('encrypted-value')
    expect(query.params[1]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1) // single batch
  })

  it('notInArray on text_eq emits eq_term <> hmac_256 per value, AND-combined', async () => {
    const { protectOps, dialect } = setupV3()
    const condition = await protectOps.notInArray(table.t_eq, ['alice', 'bob'])
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('eql_v3.eq_term(')
    expect(query.sql).toContain('eql_v3.hmac_256(')
    expect(query.sql).toContain('<>')
    expect(query.sql.toLowerCase()).toContain(' and ')
    expect(query.params).toHaveLength(2)
  })
})

describe('v3 ordering helpers route through the dialect seam', () => {
  it.each(['asc', 'desc'] as const)(
    '%s on text_ord sorts by ord_term(column)',
    (dir) => {
      const { protectOps, dialect } = setupV3()
      const condition = protectOps[dir](table.t_ord)
      const query = dialect.sqlToQuery(condition)
      expect(query.sql).toContain('eql_v3.ord_term(')
      expect(query.sql.toLowerCase()).toContain(dir)
    },
  )
})

describe('v3 lazy operators combine under and()', () => {
  it('and(eq, lt) emits both eq_term and ord_term with one param each', async () => {
    const { protectOps, dialect } = setupV3()
    const [eqCond, ltCond] = await Promise.all([
      protectOps.eq(table.t_eq, 'alice'),
      protectOps.lt(table.t_ord, 'm'),
    ])
    const combined = and(eqCond, ltCond)
    if (!combined) throw new Error('expected a combined condition')
    const query = dialect.sqlToQuery(combined)
    expect(query.sql).toContain('eql_v3.eq_term(')
    expect(query.sql).toContain('eql_v3.ord_term(')
    expect(query.sql.toLowerCase()).toContain(' and ')
    expect(query.params).toHaveLength(2)
  })
})

describe('v3 dialect leaves non-encrypted columns on the native path', () => {
  it('gt on a plain column emits native > and does not encrypt', async () => {
    const { protectOps, dialect, encryptQuery } = setupV3()
    const condition = await protectOps.gt(plainTable.age, 5)
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('>')
    expect(query.sql).not.toContain('eql_v3')
    expect(encryptQuery).not.toHaveBeenCalled()
  })

  it('like on a plain column emits native like and does not encrypt', async () => {
    const { protectOps, dialect, encryptQuery } = setupV3()
    const condition = await protectOps.like(plainTable.name, 'a%')
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('like')
    expect(query.sql).not.toContain('eql_v3')
    expect(encryptQuery).not.toHaveBeenCalled()
  })

  it('between on a plain column emits native between and does not encrypt', async () => {
    const { protectOps, dialect, encryptQuery } = setupV3()
    const condition = await protectOps.between(plainTable.age, 1, 5)
    const query = dialect.sqlToQuery(condition)
    expect(query.sql).toContain('between')
    expect(query.sql).not.toContain('eql_v3')
    expect(encryptQuery).not.toHaveBeenCalled()
  })
})
