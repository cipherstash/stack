import { isCipherstashV3CodecId } from '../extension-metadata/constants'

export type EqualityOp = 'eq' | 'ne'
export type ComparisonOp = 'gt' | 'gte' | 'lt' | 'lte'
export type MatchOp = 'like' | 'ilike'

/**
 * SQL-dialect seam (mirrors packages/drizzle/src/pg/sql-dialect.ts). The operator
 * factories read template strings from here, so v2 and v3 share all lowering
 * plumbing and differ only in this object. Templates use the framework's
 * {{self}} / {{argN}} placeholders.
 */
export interface SqlDialect {
  equality(op: EqualityOp): string
  comparison(op: ComparisonOp): string
  range(): string
  match(op: MatchOp): string
}

export const v2Dialect: SqlDialect = {
  equality: (op) => (op === 'eq' ? 'eql_v2.eq({{self}}, {{arg0}})' : 'NOT eql_v2.eq({{self}}, {{arg0}})'),
  comparison: (op) => `eql_v2.${op}({{self}}, {{arg0}})`,
  range: () => 'eql_v2.gte({{self}}, {{arg0}}) AND eql_v2.lte({{self}}, {{arg1}})',
  match: (op) => `eql_v2.${op === 'like' ? 'ilike' : op}({{self}}, {{arg0}})`,
}

const ORD_SYMBOL: Record<ComparisonOp, string> = { gt: '>', gte: '>=', lt: '<', lte: '<=' }

/**
 * v3 emission. v3 queries compare EXTRACTED INDEX TERMS, not encrypted payloads:
 * the domains CHECK a full payload {v,i,c,…}, but a search term is index-only, so
 * native (domain, jsonb) operators — which coerce the param into the domain —
 * fail the CHECK (SQLSTATE 23514). Column-side extractors take the column domain
 * (has `c`); jsonb-side helpers pull the index field straight out of the search
 * term with no coercion.
 *
 * Scalar-AGNOSTIC: the column-side extractors are overloaded per domain (Postgres
 * resolves by the column's type) and the jsonb-side helpers are shared across
 * scalars — so adding scalar #2 is a domain-map row, not a new dialect.
 */
export const v3Dialect: SqlDialect = {
  equality: (op) => `eql_v3.eq_term({{self}}) ${op === 'eq' ? '=' : '<>'} eql_v3.hmac_256({{arg0}}::jsonb)`,
  comparison: (op) => `eql_v3.ord_term({{self}}) ${ORD_SYMBOL[op]} eql_v3.ore_block_u64_8_256({{arg0}}::jsonb)`,
  range: () =>
    'eql_v3.ord_term({{self}}) >= eql_v3.ore_block_u64_8_256({{arg0}}::jsonb) AND ' +
    'eql_v3.ord_term({{self}}) <= eql_v3.ore_block_u64_8_256({{arg1}}::jsonb)',
  match: () => 'eql_v3.match_term({{self}}) @> eql_v3.bloom_filter({{arg0}}::jsonb)',
}

// Route by codec id: a column's wire/operator family is fixed by its codec id,
// not by which operator is applied.
export function dialectForCodecId(codecId: string): SqlDialect {
  return isCipherstashV3CodecId(codecId) ? v3Dialect : v2Dialect
}
