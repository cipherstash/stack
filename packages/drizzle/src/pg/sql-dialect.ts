import { type SQL, sql } from 'drizzle-orm'

export type EqualityOp = 'eq' | 'ne'
export type ComparisonOp = 'gt' | 'gte' | 'lt' | 'lte'
export type MatchOp = 'like' | 'ilike'

/**
 * The SQL-dialect seam (spec §5.2). The operator factories in operators.ts read
 * their templates from here, so v2 and v3 share all lazy/batch plumbing and differ
 * only in this object.
 *
 * `left` is the column SQL; `enc`/`min`/`max` are bound encrypted-param SQL
 * fragments (already wrapped via bindIfParam by the caller).
 *
 * `equality` is in the seam (unlike the original plan, which kept eq/ne on the
 * native Drizzle eq/ne path): v3's `text_eq` domain CHECK requires {v,i,c,hm}, but
 * an equality SEARCH term carries only {i,v,hm} (no ciphertext). Letting Postgres
 * coerce the param to `text_eq` therefore fails `text_eq_check` (SQLSTATE 23514).
 * Casting the param to `jsonb` binds the `= (text_eq, jsonb)` operator (function
 * eql_v3.eq) instead, which compares hmacs without coercing the param. Confirmed
 * by the Task 12 round-trip.
 */
export type SqlDialect = {
  equality(op: EqualityOp, left: SQL, enc: SQL): SQL
  comparison(op: ComparisonOp, left: SQL, enc: SQL): SQL
  range(left: SQL, min: SQL, max: SQL): SQL
  match(op: MatchOp, left: SQL, enc: SQL): SQL
  orderBy(column: SQL): SQL
}

export const v2Dialect: SqlDialect = {
  equality(op, left, enc) {
    return op === 'eq' ? sql`${left} = ${enc}` : sql`${left} <> ${enc}`
  },
  comparison(op, left, enc) {
    return sql`eql_v2.${sql.raw(op)}(${left}, ${enc})`
  },
  range(left, min, max) {
    return sql`eql_v2.gte(${left}, ${min}) AND eql_v2.lte(${left}, ${max})`
  },
  match(op, left, enc) {
    return sql`eql_v2.${sql.raw(op)}(${left}, ${enc})`
  },
  orderBy(column) {
    return sql`eql_v2.order_by(${column})`
  },
}

const ORD_SYMBOL: Record<ComparisonOp, string> = {
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
}

/**
 * v3 emission (spec §5.2), reconciled against release/cipherstash-encrypt-v3.sql
 * (EQL 035952e) in plan Task 12.
 *
 * v3 queries compare EXTRACTED INDEX TERMS, not the encrypted payloads directly.
 * Why: the v3 domains (`text_eq`, `text_ord`, `text_match`) have CHECK constraints
 * requiring a full payload `{v,i,c,…}` INCLUDING ciphertext `c`. A protect SEARCH
 * term is index-only (`{i,v,hm}` / `…ob` / `…bf}`, no `c`), so casting it to the
 * domain — which every native `(domain, jsonb)` operator function does internally
 * (`eq_term(a) = eq_term(b::text_eq)`) — fails `*_check` (SQLSTATE 23514).
 *
 * Instead we extract on both sides and compare the index terms:
 *   - column side: `eq_term`/`ord_term`/`match_term` take the column DOMAIN (the
 *     stored value has `c`, so it passes the CHECK);
 *   - search side: the jsonb helper extractors `hmac_256(jsonb)` /
 *     `ore_block_u64_8_256(jsonb)` / `bloom_filter(jsonb)` pull the index field
 *     straight out of the search-term jsonb with NO domain coercion (no CHECK).
 * The extracted types carry the real comparison operators: hmac_256 `=`/`<>`,
 * ore_block_u64_8_256 `<`/`<=`/`>`/`>=`, bloom_filter `@>` containment.
 *
 * This form is scalar-AGNOSTIC: the column-side extractors are overloaded per
 * domain (Postgres resolves by the column's type) and the jsonb-side helpers are
 * shared across scalars. So no scalar name is hardcoded here — adding scalar #2 is
 * a domain-map row, not a new dialect (resolves the plan Task 7 limitation note).
 */
export const v3Dialect: SqlDialect = {
  equality(op, left, enc) {
    const cmp = op === 'eq' ? sql.raw('=') : sql.raw('<>')
    return sql`eql_v3.eq_term(${left}) ${cmp} eql_v3.hmac_256(${enc}::jsonb)`
  },
  comparison(op, left, enc) {
    return sql`eql_v3.ord_term(${left}) ${sql.raw(ORD_SYMBOL[op])} eql_v3.ore_block_u64_8_256(${enc}::jsonb)`
  },
  range(left, min, max) {
    return sql`eql_v3.ord_term(${left}) >= eql_v3.ore_block_u64_8_256(${min}::jsonb) AND eql_v3.ord_term(${left}) <= eql_v3.ore_block_u64_8_256(${max}::jsonb)`
  },
  match(_op, left, enc) {
    // containment match: column bloom filter @> search-term bloom filter
    return sql`eql_v3.match_term(${left}) @> eql_v3.bloom_filter(${enc}::jsonb)`
  },
  orderBy(column) {
    return sql`eql_v3.ord_term(${column})`
  },
}
