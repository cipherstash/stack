export { eqlV3Type, type EqlV3Config } from './eql-v3-type.js'
export {
  eqlV3Domain,
  v3CastAs,
  type V3DataType,
  type V3Index,
} from './domain-map.js'
export { v3FromDriver, v3ToDriver } from './codec.js'
export { v3Dialect, type SqlDialect } from '../sql-dialect.js'
// Shared with v2 — re-exported for a single v3 import site:
export { extractProtectSchema } from '../schema-extraction.js'
import type { ProtectClient } from '@cipherstash/protect/client'
import { createProtectOperators as createProtectOperatorsBase } from '../operators.js'
import { v3Dialect } from '../sql-dialect.js'
export { ProtectOperatorError, ProtectConfigError } from '../operators.js'

/**
 * Operators with the v3 dialect pre-bound. On the ./pg/v3 import path this IS
 * `createProtectOperators` (and the explicit `createProtectOperatorsV3` alias), so
 * a v3 consumer can't accidentally reach the v2-defaulted factory — which would
 * emit eql_v2/native SQL that fails the v3 domain CHECKs at runtime. The
 * dialect-parameterised factory is still available from '@cipherstash/drizzle/pg'.
 */
export function createProtectOperators(client: ProtectClient) {
  return createProtectOperatorsBase(client, v3Dialect)
}
export const createProtectOperatorsV3 = createProtectOperators
