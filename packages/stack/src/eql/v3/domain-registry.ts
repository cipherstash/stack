import type { AnyEncryptedV3Column } from './columns'
import { types } from './types'

/** A factory that builds a concrete v3 column for a given DB column name. */
export type V3ColumnFactory = (name: string) => AnyEncryptedV3Column

/**
 * Unqualified Postgres `domain_name` → the existing `types` factory. Values are
 * the `eql/v3/types.ts` factories (which pass the literal domain constants),
 * NOT direct `new EncryptedXColumn(...)` calls — the constant carried by each
 * factory is what keeps the domains nominally distinct. `TextSearch` has a
 * different arity, so this is a value map, not a mechanical transform.
 */
// NULL PROTOTYPE — load-bearing. A plain object literal inherits from
// Object.prototype, so `DOMAIN_REGISTRY['constructor']` returns a *function*
// and passes a truthiness check. A column whose domain is named `constructor`,
// `toString`, `valueOf` or `__proto__` would then be treated as a modelled EQL
// domain and "synthesized" from Object.prototype.constructor. `factoryForDomain`
// additionally guards with `Object.hasOwn`; both are kept — belt and braces,
// because a future refactor that drops the null prototype must not silently
// reopen the hole.
export const DOMAIN_REGISTRY: Record<string, V3ColumnFactory> = Object.assign(
  Object.create(null) as Record<string, V3ColumnFactory>,
  {
    // integer
    integer: types.Integer,
    integer_eq: types.IntegerEq,
    integer_ord_ore: types.IntegerOrdOre,
    integer_ord: types.IntegerOrd,
    // smallint
    smallint: types.Smallint,
    smallint_eq: types.SmallintEq,
    smallint_ord_ore: types.SmallintOrdOre,
    smallint_ord: types.SmallintOrd,
    // bigint
    bigint: types.Bigint,
    bigint_eq: types.BigintEq,
    bigint_ord_ore: types.BigintOrdOre,
    bigint_ord: types.BigintOrd,
    // date
    date: types.Date,
    date_eq: types.DateEq,
    date_ord_ore: types.DateOrdOre,
    date_ord: types.DateOrd,
    // timestamp
    timestamp: types.Timestamp,
    timestamp_eq: types.TimestampEq,
    timestamp_ord_ore: types.TimestampOrdOre,
    timestamp_ord: types.TimestampOrd,
    // numeric
    numeric: types.Numeric,
    numeric_eq: types.NumericEq,
    numeric_ord_ore: types.NumericOrdOre,
    numeric_ord: types.NumericOrd,
    // text
    text: types.Text,
    text_eq: types.TextEq,
    text_match: types.TextMatch,
    text_ord_ore: types.TextOrdOre,
    text_ord: types.TextOrd,
    text_search: types.TextSearch,
    // boolean
    boolean: types.Boolean,
    // real
    real: types.Real,
    real_eq: types.RealEq,
    real_ord_ore: types.RealOrdOre,
    real_ord: types.RealOrd,
    // double
    double: types.Double,
    double_eq: types.DoubleEq,
    double_ord_ore: types.DoubleOrdOre,
    double_ord: types.DoubleOrd,
  },
)

/** Strip a leading `public.` schema qualifier from a qualified `eqlType`. */
export function stripDomainSchema(eqlType: string): string {
  return eqlType.startsWith('public.')
    ? eqlType.slice('public.'.length)
    : eqlType
}

/**
 * Look up the factory for an unqualified domain name, or `undefined`.
 *
 * `Object.hasOwn` is required, not decorative: without it a domain named
 * `constructor` / `toString` / `valueOf` / `__proto__` resolves to an inherited
 * `Object.prototype` member and violates the "unknown domain = plaintext" rule.
 */
export function factoryForDomain(
  domainName: string,
): V3ColumnFactory | undefined {
  return Object.hasOwn(DOMAIN_REGISTRY, domainName)
    ? DOMAIN_REGISTRY[domainName]
    : undefined
}
