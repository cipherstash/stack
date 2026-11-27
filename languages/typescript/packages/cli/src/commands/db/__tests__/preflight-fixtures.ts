import type { PreflightResult } from '@/installer/index.js'

/** A preflight result for a role that can install EQL with no gaps. */
export const CAPABLE: PreflightResult = {
  currentUser: 'postgres',
  isSuperuser: true,
  memberOfPostgres: true,
  hasDatabaseCreate: true,
  hasPublicCreate: true,
  pgcryptoInstalled: true,
  pgcryptoSchema: 'extensions',
  eqlV3SchemaPresent: false,
  eqlV3InternalSchemaPresent: false,
  canDropEqlV3Schema: null,
  canDropEqlV3InternalSchema: null,
  canCreateOperatorClass: true,
  missing: [],
  ok: true,
}
