import type { QueryCapabilities } from '@cipherstash/stack/eql/v3'

/** Every query operation an adapter can be asked to perform on an encrypted column. */
export type QueryOpKind =
  | 'eq'
  | 'ne'
  | 'in'
  | 'notIn'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'between'
  | 'notBetween'
  | 'contains'
  | 'order'
  | 'isNull'
  | 'isNotNull'

export type Plain = string | number | bigint | boolean | Date

export type QueryOp =
  | {
      kind: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte'
      column: string
      value: Plain
    }
  | {
      kind: 'in' | 'notIn'
      column: string
      values: readonly Plain[]
      /**
       * Supabase only: drive the raw `.filter(col, 'in', […])` path instead of
       * `.in()`. They are different code paths — the raw path reached `in` with
       * no element-split and encrypted the whole list as one term — so both
       * must be proven against the same oracle.
       */
      asRawFilter?: boolean
    }
  | { kind: 'between' | 'notBetween'; column: string; lo: Plain; hi: Plain }
  | { kind: 'contains'; column: string; needle: string }
  | { kind: 'order'; column: string; direction: 'asc' | 'desc' }
  | { kind: 'isNull' | 'isNotNull'; column: string }

/**
 * Which operations each capability unlocks. This table is the ONLY place the
 * mapping lives: the positive tests and the rejection tests are both derived
 * from it, so flipping a capability flag in the catalog turns a passing
 * rejection into a failing query (and vice versa) rather than silently
 * disagreeing with the SDK.
 *
 * `orderAndRange` implies equality in the SDK's presets, but that is a property
 * of the CATALOG rows (`ORD` sets `equality: true`), not of this table — do not
 * encode the implication twice.
 */
const OPS_BY_CAPABILITY = {
  equality: ['eq', 'ne', 'in', 'notIn'],
  orderAndRange: ['gt', 'gte', 'lt', 'lte', 'between', 'notBetween', 'order'],
  freeTextSearch: ['contains'],
  // Encrypted-JSONB containment surfaces as `contains` too (doc @> subset), but
  // json domains are `deferred` from this driver (ste_vec doesn't fit the scalar
  // oracle) and covered by a dedicated suite, so this entry exists to satisfy
  // the capability-keyed type rather than to gate a run.
  searchableJson: ['contains'],
} as const satisfies Record<keyof QueryCapabilities, readonly QueryOpKind[]>

/**
 * Null presence is structural, not cryptographic: a NULL plaintext is stored as
 * a SQL NULL on every domain, including storage-only ones. So `isNull` /
 * `isNotNull` are never capability-gated, and never appear in the rejection set.
 */
const STRUCTURAL_OPS: readonly QueryOpKind[] = ['isNull', 'isNotNull']

function enabledBy(kind: QueryOpKind, caps: QueryCapabilities): boolean {
  return (
    Object.keys(OPS_BY_CAPABILITY) as Array<keyof QueryCapabilities>
  ).some(
    (cap) =>
      caps[cap] &&
      (OPS_BY_CAPABILITY[cap] as readonly QueryOpKind[]).includes(kind),
  )
}

/** Operations this adapter supports AND this domain's capabilities allow. Must succeed. */
export function positiveOps(
  caps: QueryCapabilities,
  supported: ReadonlySet<QueryOpKind>,
): Set<QueryOpKind> {
  return new Set([...supported].filter((kind) => enabledBy(kind, caps)))
}

/**
 * Operations this adapter supports but this domain's capabilities forbid. Must
 * be rejected — by a compile error in typed usage, and by a thrown error here.
 * Structural ops are excluded: they are legal on every domain.
 */
export function negativeOps(
  caps: QueryCapabilities,
  supported: ReadonlySet<QueryOpKind>,
): Set<QueryOpKind> {
  return new Set(
    [...supported].filter(
      (kind) => !enabledBy(kind, caps) && !STRUCTURAL_OPS.includes(kind),
    ),
  )
}
