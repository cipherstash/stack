/**
 * Internal support surface for FIRST-PARTY adapter packages
 * (`@cipherstash/stack-supabase`, `@cipherstash/stack-drizzle`).
 *
 * These symbols were previously reached through deep `@/` internal imports while
 * the Supabase and Drizzle adapters lived INSIDE this package. Splitting them into
 * their own packages (see issue #627) means those imports must resolve across a
 * package boundary — so exactly the symbols the adapters consume are re-exported
 * here, from one narrow, versioned entry point, rather than leaking six internal
 * module paths into the public surface.
 *
 * NOT a general-purpose public API. This is the seam between core and the
 * first-party adapters; treat it as `@internal`-adjacent. Anything an END USER
 * should reach has a dedicated subpath (`./schema`, `./eql/v3`, `./types`,
 * `./identity`, `./errors`). If a symbol here graduates to genuine public use,
 * promote it to one of those instead of widening this file's contract.
 *
 * The full member list is small on purpose; every addition is an audit decision.
 */

// Model → encrypted-PG-composite helpers used by the v2 Supabase mutation path.
export {
  bulkModelsToEncryptedPgComposites,
  modelToEncryptedPgComposites,
} from './encryption/helpers/index.js'

// Audit config carried by chainable operations.
export type { AuditConfig } from './encryption/operations/base-operation.js'

// v3 column model + the date-like cast set the Supabase builder uses to
// reconstruct `Date` values from PostgREST select aliases.
export {
  type AnyEncryptedV3Column,
  DATE_LIKE_CASTS,
  EncryptedV3Column,
} from './eql/v3/columns.js'

// Domain registry: the Supabase adapter classifies introspected columns by their
// Postgres domain and rebuilds each column's encryption config from it.
export {
  DOMAIN_REGISTRY,
  factoryForDomain,
  stripDomainSchema,
} from './eql/v3/domain-registry.js'

// Shared match-index guard (short-needle rejection), reused by both adapters.
export { matchNeedleError } from './schema/match-defaults.js'
// Shared structured logger (adapters log rejections through the same instance).
export { logger } from './utils/logger/index.js'
