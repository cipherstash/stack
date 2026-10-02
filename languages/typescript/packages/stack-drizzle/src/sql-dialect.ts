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

/**
 * Emit the EQL v3 comparison/containment SQL. Every operand `enc` arrives ALREADY
 * cast to its `eql_v3.query_<domain>` type by the operator layer (see
 * `operators.ts` — the term comes from `encryptQuery`, so it is ciphertext-free
 * and matches the `query_<domain>` CHECK). The dialect therefore adds no cast of
 * its own; it only places the pre-cast operand into the right function/operator.
 * This reaches the `(domain, query_<domain>)` overloads the bundle defines for
 * narrowed query terms, rather than the `(domain, jsonb)` overload that coerces
 * to the storage domain and demands the ciphertext `c`.
 */
export const v3Dialect = {
  equality(op: EqualityOp, left: SQL, enc: SQL): SQL {
    return sql`${fn(op === 'eq' ? 'eq' : 'neq')}(${left}, ${enc})`
  },

  comparison(op: ComparisonOp, left: SQL, enc: SQL): SQL {
    return sql`${fn(op)}(${left}, ${enc})`
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
    return sql`(${fn('gte')}(${left}, ${min}) AND ${fn('lte')}(${left}, ${max}))`
  },

  contains(left: SQL, enc: SQL): SQL {
    return sql`${fn('matches')}(${left}, ${enc})`
  },

  /**
   * Encrypted-JSONB containment (`eql_v3_json_search @> sub-document`). Unlike text,
   * json has NO `eql_v3.matches` overload — containment is the `@>` operator,
   * whose `(eql_v3_json_search, eql_v3.query_json)` form takes the `query_json` needle
   * the operator layer produced. The four `eql_v3_json_search @> ?` RHS overloads mean a
   * bare operand would be ambiguous ("operator is not unique", 42725), so the
   * needle is pre-cast to `eql_v3.query_json` upstream (see
   * `encryptJsonContainmentTerm`).
   */
  containsJson(left: SQL, enc: SQL): SQL {
    return sql`${left} OPERATOR(public.@>) ${enc}`
  },

  /** Extract the encrypted JSON leaf entry addressed by a selector hash. */
  selectorEntry(source: SQL, selector: SQL): SQL {
    // Keep the canonical operator shape: functional indexes are defined over
    // `eql_v3.ord_term(col -> selector)`. The RHS is explicitly `text` upstream
    // so PostgreSQL selects EQL's encrypted-JSON accessor, not native jsonb `->`.
    return sql`${source} -> ${selector}`
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
