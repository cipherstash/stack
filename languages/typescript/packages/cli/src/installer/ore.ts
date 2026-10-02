import { EQL_V3_INTERNAL_SCHEMA_NAME } from './grants.js'

/**
 * The ORE half of an EQL install, in one place (#891).
 *
 * The EQL bundle wraps `CREATE OPERATOR CLASS` for the ORE btree opclass in a
 * guarded `DO` block that swallows `insufficient_privilege` (42501). Where the
 * installing role cannot clear that gate, the class is skipped and the bundle
 * poisons every `_ord_ore` / `_search_ore` domain with an always-raising
 * `eql_ore_unavailable` CHECK instead — so the gap fails loudly at write time
 * rather than silently producing an index that never engages.
 *
 * That is a supported configuration, not a failed install. What it costs the
 * operator is the ORE ordering flavour; the OPE one (`types.*Ord`) orders and
 * indexes on any role. This module holds the catalogue probe, the state
 * machine over it, and the single copy every command uses to say so — before
 * the install (`eql preflight`), at the install (`eql install`), and after it
 * (`eql status`, `eql verify`). The failure this addresses was an operator
 * discovering the trade at query time.
 */

/**
 * Whether the default btree opclass over `eql_v3_internal.ore_block_256`
 * exists. Mirrors the EQL bundle's own fallback test (`ore_fallback.sql`) with
 * one deliberate difference: `to_regtype` returns NULL where the bundle's
 * `::regtype` cast raises, so this degrades to `false` on a database with no
 * EQL installed instead of throwing. Callers that care about the difference
 * detect "not installed" separately.
 *
 * A bare SQL *expression*, so callers can select it alone or fold it into a
 * wider row.
 */
export const ORE_OPCLASS_PRESENT_EXPR = `EXISTS (
    SELECT 1
    FROM pg_catalog.pg_opclass c
    JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
    WHERE am.amname = 'btree'
      AND c.opcdefault
      AND c.opcintype = to_regtype('${EQL_V3_INTERNAL_SCHEMA_NAME}.ore_block_256')
  )`

/**
 * How the ORE half of an install reads. Only the first two are healthy: the
 * bundle either created the operator class (privileged install) or skipped it
 * and poisoned every ORE domain so the gap fails loudly (the managed-Postgres
 * install). The two `incoherent-*` states are half-applied combinations the
 * bundle never produces on its own.
 */
export type OreSurfaceState =
  | 'indexable'
  | 'fallback'
  | 'incoherent-unpoisoned'
  | 'incoherent-poisoned'

/** Classify an observed ORE state. Pure. */
export function classifyOreState(observed: {
  opclassPresent: boolean
  poisonedDomains: number
  expectedPoisoned: number
}): OreSurfaceState {
  if (observed.opclassPresent) {
    return observed.poisonedDomains === 0 ? 'indexable' : 'incoherent-poisoned'
  }
  return observed.poisonedDomains === observed.expectedPoisoned
    ? 'fallback'
    : 'incoherent-unpoisoned'
}

/**
 * The remedy, named once.
 *
 * It deliberately names `types.*Ord` and not the `_ord_ope` domains: the
 * bundle creates `public.eql_v3_<t>_ord_ope`, but `@cipherstash/stack` ships
 * no `types.*OrdOpe` factory, so pointing a schema author there names a column
 * type they cannot declare. `types.*Ord` (`public.eql_v3_<t>_ord`) is the same
 * CLLW-OPE ordering and is the one with an SDK factory behind it.
 */
export const ORE_FALLBACK_REMEDY =
  'Ordered columns must use OPE ordering: declare them `types.*Ord` (`public.eql_v3_*_ord`), which orders and indexes on any role. `types.*OrdOre` is unusable here — every write to one fails its `eql_ore_unavailable` CHECK.'

/**
 * One line naming what an ORE state means for the operator. `severity` is what
 * a caller should render it as; `'info'` states are not damage.
 */
export function describeOreState(state: OreSurfaceState): {
  severity: 'info' | 'damage'
  /** Short value for a report row. */
  value: string
  /** Full sentence, consequence and remedy included. */
  message: string
} {
  switch (state) {
    case 'indexable':
      return {
        severity: 'info',
        value: 'present',
        message:
          'ORE operator class present — the `types.*OrdOre` domains are usable and ORE ordered indexes engage.',
      }
    case 'fallback':
      return {
        severity: 'info',
        value: 'skipped (expected on managed Postgres)',
        message: `ORE operator class not created — this role cannot create one, and the EQL bundle installed its loud-failure fallback instead. This is the supported managed-Postgres configuration, not a failed install. ${ORE_FALLBACK_REMEDY}`,
      }
    case 'incoherent-poisoned':
      return {
        severity: 'damage',
        value: 'INCOHERENT',
        message:
          'The ORE operator class exists, but ORE domains still carry the `eql_ore_unavailable` poison CHECK — writes to those domains fail although ORE works. Reinstall with `stash eql install --force`.',
      }
    case 'incoherent-unpoisoned':
      return {
        severity: 'damage',
        value: 'INCOHERENT',
        message:
          'The ORE operator class is absent, but only some ORE domains carry the loud-failure fallback — the rest would fail at index/ORDER BY time with opaque errors instead. Reinstall with `stash eql install --force`.',
      }
  }
}

/**
 * What `eql preflight` can say about ORE *before* anything is installed.
 *
 * `null` is "could not determine" and must never be rendered as either answer.
 */
export function describeOreCreatable(creatable: boolean | null): {
  value: string
  annotation?: string
} {
  if (creatable === null) {
    return {
      value: 'unknown',
      annotation:
        '<- could not probe; `stash eql verify` reports it after install',
    }
  }
  if (creatable) return { value: 'creatable' }
  return {
    value: 'not creatable',
    annotation: '<- skips: ORE opclass; use `types.*Ord`, not `types.*OrdOre`',
  }
}
