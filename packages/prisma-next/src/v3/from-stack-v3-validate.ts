/**
 * v3 override validation for `cipherstashFromStackV3`.
 *
 * Compares EXACT domain identity (`getEqlType()` → `public.eql_v3_*`),
 * not the v2 rule of cast_as + installed-index-set equivalence:
 * `integer_ord` and `integer_ord_ore` share `cast_as: number` and an
 * ordering index family, but are different domains whose on-disk CHECK
 * constraints and query operand types (`eql_v3.query_integer_ord` vs
 * `eql_v3.query_integer_ord_ore`) diverge — an override that swaps one
 * for the other would produce query terms the installed domain rejects.
 */

import type { AnyV3Table } from '@cipherstash/stack/eql/v3'

/**
 * Assert that a user-supplied v3 table override agrees with the
 * contract-derived table on every column: same column set (keyed by the
 * physical DB column name) and, per column, the same concrete
 * `public.eql_v3_*` domain. Throws with a fix-the-schema hint on the
 * first divergence.
 */
export function assertV3SchemasAgree(
  derived: AnyV3Table,
  override: AnyV3Table,
): void {
  const derivedDomains = domainsByColumn(derived)
  const overrideDomains = domainsByColumn(override)

  const columns = new Set([...derivedDomains.keys(), ...overrideDomains.keys()])
  for (const column of [...columns].sort()) {
    const derivedDomain = derivedDomains.get(column)
    const overrideDomain = overrideDomains.get(column)
    if (derivedDomain !== overrideDomain) {
      throw new Error(
        `cipherstashFromStackV3: schema divergence on column "${derived.tableName}"."${column}". ` +
          `Contract domain "${derivedDomain ?? '(missing)'}" but override domain "${overrideDomain ?? '(missing)'}". ` +
          'Overrides must match the contract exactly on contract-declared tables — ' +
          'fix prisma/schema.prisma and re-emit rather than overriding.',
      )
    }
  }
}

function domainsByColumn(table: AnyV3Table): Map<string, string> {
  const domains = new Map<string, string>()
  for (const builder of Object.values(table.columnBuilders)) {
    domains.set(builder.getName(), builder.getEqlType())
  }
  return domains
}
