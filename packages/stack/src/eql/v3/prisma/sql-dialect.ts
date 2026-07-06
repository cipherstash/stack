/**
 * EQL v3 SQL emission for the Prisma integration.
 *
 * Lowering targets the CURRENT vendored bundle (protect-ffi 0.27 line):
 * the public two-arg function forms — `eql_v3.eq(col, $::jsonb)`,
 * `eql_v3.contains(col, $::jsonb)`, … — which coerce the jsonb operand into
 * the column's domain and compare the right index term for that domain
 * (including equality-via-ORE on order-only domains). Because the operand is
 * coerced into the domain, it MUST be a full storage envelope that passes the
 * domain CHECK; see `encryptOperand` in where.ts (the single swap point,
 * CIP-3402/CIP-3423). This mirrors the Drizzle v3 dialect's SHAPE, not its
 * SQL — that branch targets a different bundle generation with public
 * term-only constructors.
 *
 * Fragments are assembled with the CALLER-INJECTED `Prisma.sql` (from the
 * user's generated client) so the values travel as bound parameters and the
 * result composes into `$queryRaw` untouched. Identifiers are always
 * double-quoted with embedded quotes doubled.
 */

/** The `Prisma.sql` tag, callable with a plain strings array. */
export type SqlTag = (
  strings: ReadonlyArray<string>,
  ...values: unknown[]
) => unknown

export type BinaryFn = 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains'

/** Quote a SQL identifier, doubling embedded double quotes. */
export function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`
}

export const v3PrismaDialect = {
  /** `eql_v3.<fn>(<col>, $1::jsonb)` */
  binary(sql: SqlTag, fn: BinaryFn, ident: string, operand: string): unknown {
    return sql([`eql_v3.${fn}(${ident}, `, '::jsonb)'], operand)
  },

  /** `(eql_v3.gte(<col>, $1::jsonb) AND eql_v3.lte(<col>, $2::jsonb))` */
  between(
    sql: SqlTag,
    ident: string,
    min: string,
    max: string,
    negate: boolean,
  ): unknown {
    const prefix = negate ? 'NOT (' : '('
    return sql(
      [
        `${prefix}eql_v3.gte(${ident}, `,
        `::jsonb) AND eql_v3.lte(${ident}, `,
        '::jsonb))',
      ],
      min,
      max,
    )
  },

  /**
   * `(eql_v3.eq(<col>, $1::jsonb) OR eql_v3.eq(<col>, $2::jsonb) …)` —
   * `fn`/`joiner` are `eq`/`OR` for IN, `neq`/`AND` for NOT IN.
   */
  list(
    sql: SqlTag,
    fn: 'eq' | 'neq',
    joiner: 'OR' | 'AND',
    ident: string,
    operands: string[],
  ): unknown {
    const call = `eql_v3.${fn}(${ident}, `
    const strings = [
      `(${call}`,
      ...operands.slice(1).map(() => `::jsonb) ${joiner} ${call}`),
      '::jsonb))',
    ]
    return sql(strings, ...operands)
  },

  /** `eql_v3.ord_term(<col>) ASC|DESC` — for interpolation after ORDER BY. */
  ordTerm(sql: SqlTag, ident: string, direction: 'ASC' | 'DESC'): unknown {
    return sql([`eql_v3.ord_term(${ident}) ${direction}`])
  },

  /** `<col> IS [NOT] NULL` */
  nullCheck(sql: SqlTag, ident: string, negate: boolean): unknown {
    return sql([`${ident} IS ${negate ? 'NOT ' : ''}NULL`])
  },
}
