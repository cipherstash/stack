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
 *
 * This barrel MUST NOT import `vitest`, directly or transitively. Vitest's
 * `globalSetup` runs in a different context from the test workers, and a
 * `vitest` import reached from there fails with "Vitest failed to access its
 * internal state". `global-setup.ts` imports this barrel, so the test driver
 * lives behind its own subpath: `@cipherstash/test-kit/suite`.
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
  databaseUrl,
  pgrestUrl,
  type Requirement,
  requireIntegrationEnv,
} from './env.ts'
export {
  deferredForFamily,
  domainsForFamily,
  FAMILY_NAMES,
  type FamilyDomain,
  type FamilyName,
} from './families.ts'
export { type DbVariant, dbVariant, installEqlV3 } from './install.ts'
export type {
  JsonIntegrationAdapter,
  JsonQueryOp,
  JsonScalar,
  JsonSeedRow,
  JsonTableSpec,
} from './json-adapter.ts'
export { needleFor } from './needle-for.ts'
export {
  negativeOps,
  type Plain,
  positiveOps,
  type QueryOp,
  type QueryOpKind,
} from './ops.ts'
export {
  comparePlain,
  expectedKeysFor,
  matchesPlain,
  plainValue,
  sortedKeysFor,
} from './oracle.ts'
export { unwrapResult } from './results.ts'
export {
  NULL_ROW_KEY,
  type PlainRow,
  planRows,
  planTable,
  type RowPlan,
  type TableSpec,
} from './rows.ts'
