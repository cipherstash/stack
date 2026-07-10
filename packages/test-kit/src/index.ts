/**
 * Shared EQL v3 test harness.
 *
 * The domain catalog is the single source of truth: it is
 * `satisfies Record<EqlV3TypeName, DomainSpec>` over the real column union, so
 * adding a domain to the SDK fails this package's typecheck until a row exists.
 * Everything else here derives from it — which operations a domain must answer,
 * which it must reject, and what the expected rows are.
 *
 * Consumed as TypeScript source (no build). See `vitest.shared.ts` at the repo
 * root for the runtime aliases and `tsconfig.json` here for the compile-time ones.
 */

export type { IntegrationAdapter } from './adapter.ts'
export {
  type DomainSpec,
  deferredReason,
  EQL_V3_DOMAIN_SCHEMA,
  type EqlV3TypeName,
  eqlTypeSlug,
  isCovered,
  typedEntries,
  V3_MATRIX,
} from './catalog.ts'
export {
  deferredForFamily,
  domainsForFamily,
  FAMILY_NAMES,
  type FamilyDomain,
  type FamilyName,
} from './families.ts'
export {
  negativeOps,
  type Plain,
  positiveOps,
  type QueryOp,
  type QueryOpKind,
} from './ops.ts'
export {
  comparePlain,
  containsPlain,
  expectedKeysFor,
  plainValue,
  sortedKeysFor,
} from './oracle.ts'
export {
  NULL_ROW_KEY,
  type PlainRow,
  planRows,
  planTable,
  type RowPlan,
  type TableSpec,
} from './rows.ts'
