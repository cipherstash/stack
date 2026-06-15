import { createProtectOperators } from '@cipherstash/drizzle/pg'
import type { ProtectClient } from '@cipherstash/protect/client'
import { PgDialect } from 'drizzle-orm/pg-core'
import { vi } from 'vitest'
// NOTE: import from SOURCE, not the built @cipherstash/drizzle/pg — the v3 builder
// (eqlV3Type) registers config in the SOURCE module-instance columnConfigMap, and the
// SOURCE createProtectOperators is the one that accepts the dialect param. Keeping the
// v3 path on the source tree avoids module-identity mismatches (a different
// columnConfigMap, or a stale single-arg createProtectOperators in the built output).
import { createProtectOperators as createProtectOperatorsSrc } from '../src/pg/operators'
import { v3Dialect } from '../src/pg/sql-dialect'

export const ENCRYPTED_VALUE = '{"v":"encrypted-value"}'

export function createMockProtectClient() {
  const encryptQuery = vi.fn(async (termsOrValue: unknown) => {
    if (Array.isArray(termsOrValue)) {
      return { data: termsOrValue.map(() => ENCRYPTED_VALUE) }
    }
    return { data: ENCRYPTED_VALUE }
  })

  return {
    client: { encryptQuery } as unknown as ProtectClient,
    encryptQuery,
  }
}

export function setup() {
  const { client, encryptQuery } = createMockProtectClient()
  const protectOps = createProtectOperators(client)
  const dialect = new PgDialect()
  return { client, encryptQuery, protectOps, dialect }
}

export function setupV3() {
  const { client, encryptQuery } = createMockProtectClient()
  const protectOps = createProtectOperatorsSrc(client, v3Dialect)
  const dialect = new PgDialect()
  return { client, encryptQuery, protectOps, dialect }
}
