import type { AnyEncryptedV3Column } from './columns'
import { types } from './types'

/** A factory that builds a concrete v3 column for a given DB column name. */
export type V3ColumnFactory = (name: string) => AnyEncryptedV3Column

/**
 * Unqualified Postgres `domain_name` → the `eql/v3/types.ts` factory that
 * builds that domain's column.
 *
 * DERIVED, not hand-listed. Every factory already carries its domain in the
 * constant it passes to the column constructor, so the key is recoverable from
 * the factory itself — and `types` and this registry cannot drift. Adding a
 * domain to `types` is enough; forgetting an entry here is no longer possible.
 *
 * The keys are an external contract (they are the `information_schema` query
 * parameter in `../../supabase/introspect.ts`). Because they are derived from
 * `getEqlType()`, no test that also derives them can detect a corrupted domain
 * constant — `eql-v3-domain-registry.test.ts` pins them against a hand-written
 * literal list for exactly that reason.
 */
// NULL PROTOTYPE — load-bearing. A plain object literal inherits from
// Object.prototype, so `DOMAIN_REGISTRY['constructor']` returns a *function*
// and passes a truthiness check. A column whose domain is named `constructor`,
// `toString`, `valueOf` or `__proto__` would then be treated as a modelled EQL
// domain and "synthesized" from Object.prototype.constructor. `factoryForDomain`
// additionally guards with `Object.hasOwn`; both are kept — belt and braces,
// because a future refactor that drops the null prototype must not silently
// reopen the hole. It also makes the `Object.hasOwn` collision check below
// exact: on a plain object `'constructor' in registry` is spuriously true.
export const DOMAIN_REGISTRY: Record<string, V3ColumnFactory> = (() => {
  const registry = Object.create(null) as Record<string, V3ColumnFactory>
  for (const factory of Object.values(types) as V3ColumnFactory[]) {
    // Probe name only: the constructors store their arguments and nothing else,
    // so building one column per domain at module load is free of side effects.
    const key = stripDomainSchema(factory('_probe').getEqlType())
    if (Object.hasOwn(registry, key)) {
      throw new Error(`duplicate EQL v3 domain key: ${key}`)
    }
    registry[key] = factory
  }
  return registry
})()

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
