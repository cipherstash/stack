import { type SQL, sql } from 'drizzle-orm'

export type EqualityOp = 'eq' | 'ne'
export type ComparisonOp = 'gt' | 'gte' | 'lt' | 'lte'

export const v3Dialect = {
  equality(op: EqualityOp, left: SQL, enc: SQL): SQL {
    const fn = op === 'eq' ? sql.raw('eq') : sql.raw('neq')
    return sql`eql_v3.${fn}(${left}, ${enc}::jsonb)`
  },

  comparison(op: ComparisonOp, left: SQL, enc: SQL): SQL {
    return sql`eql_v3.${sql.raw(op)}(${left}, ${enc}::jsonb)`
  },

  range(left: SQL, min: SQL, max: SQL): SQL {
    return sql`eql_v3.gte(${left}, ${min}::jsonb) AND eql_v3.lte(${left}, ${max}::jsonb)`
  },

  contains(left: SQL, enc: SQL): SQL {
    return sql`eql_v3.contains(${left}, ${enc}::jsonb)`
  },

  orderBy(left: SQL): SQL {
    return sql`eql_v3.ord_term(${left})`
  },
}
