import { type SQL, sql } from 'drizzle-orm'

export type EqualityOp = 'eq' | 'ne'
export type ComparisonOp = 'gt' | 'gte' | 'lt' | 'lte'

/**
 * The schema the EQL v3 comparison functions live in. The concrete `public.*`
 * domains are derived from the column factories (see `column.ts`); the
 * functions that operate on them are namespaced separately, so they get their
 * own single source of truth.
 */
export const EQL_V3_FN_SCHEMA = 'eql_v3'

const fn = (name: string): SQL => sql.raw(`${EQL_V3_FN_SCHEMA}.${name}`)

export const v3Dialect = {
  equality(op: EqualityOp, left: SQL, enc: SQL): SQL {
    return sql`${fn(op === 'eq' ? 'eq' : 'neq')}(${left}, ${enc}::jsonb)`
  },

  comparison(op: ComparisonOp, left: SQL, enc: SQL): SQL {
    return sql`${fn(op)}(${left}, ${enc}::jsonb)`
  },

  /**
   * Inclusive range, emitted as a SELF-CONTAINED parenthesised conjunction.
   *
   * The parentheses are load-bearing: this is the only helper returning more
   * than one function call, and Drizzle's `not` renders `not ${condition}`
   * without adding any of its own. Postgres binds NOT tighter than AND, so a
   * bare fragment would make `not(between(col, x, y))` parse as
   * `(NOT gte(col, x)) AND lte(col, y)` — rows below the lower bound rather
   * than the complement of the range. Parenthesising here makes every
   * composition safe instead of asking each caller to remember.
   */
  range(left: SQL, min: SQL, max: SQL): SQL {
    return sql`(${fn('gte')}(${left}, ${min}::jsonb) AND ${fn('lte')}(${left}, ${max}::jsonb))`
  },

  contains(left: SQL, enc: SQL): SQL {
    return sql`${fn('contains')}(${left}, ${enc}::jsonb)`
  },

  orderBy(left: SQL, flavour: 'ope' | 'ore'): SQL {
    // eql-3.0.0 splits the ordering extractor by term flavour: `ord_term`
    // takes the OPE-backed `_ord` domains (returns eql_v3_internal.ope_cllw),
    // `ord_term_ore` the block-ORE `_ord_ore` domains (ore_block_256).
    return flavour === 'ore'
      ? sql`${fn('ord_term_ore')}(${left})`
      : sql`${fn('ord_term')}(${left})`
  },
}
