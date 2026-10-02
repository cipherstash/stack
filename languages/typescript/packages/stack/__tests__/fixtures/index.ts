import { expect } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'

// ============ Schema Fixtures ============

/**
 * Users table with multiple index types for testing
 */
export const users = encryptedTable('users', {
  email: types.TextEq('email'),
  bio: types.TextSearch('bio'),
  age: types.IntegerOrd('age'),
})

/**
 * Articles table with only freeTextSearch (for auto-inference test).
 *
 * MUST stay a match-only domain (`types.TextMatch`, not `types.TextSearch`):
 * `TextSearch` derives `unique + ope + match`, and `unique` outranks `match` in
 * `inferIndexType`'s priority order — which silently re-points every
 * auto-inference test here at the `hm` term and disables the match-only numeric
 * guard. Pinned by `fixtures-query-contract.test.ts`.
 */
export const articles = encryptedTable('articles', {
  content: types.TextMatch('content'),
})

/**
 * Products table with only orderAndRange (for auto-inference test).
 *
 * Deliberately the block-ORE ordering flavour (`ore` index, `ob` term), where
 * `users.age` is the CLLW-OPE one (`ope` index, `op` term), so the live suite
 * covers both v3 ordering flavours. Pinned by
 * `fixtures-query-contract.test.ts`.
 */
export const products = encryptedTable('products', {
  price: types.NumericOrdOre('price'),
})

/**
 * Metadata table with no indexes (for validation error test)
 */
export const metadata = encryptedTable('metadata', {
  raw: types.Text('raw'),
})

/**
 * Documents table with searchable JSON column (for STE Vec queries)
 */
export const jsonbSchema = encryptedTable('documents', {
  id: types.Text('id'),
  metadata: types.Json('metadata'),
})

/**
 * Schema fixture with mixed column types including JSON.
 */
export const mixedSchema = encryptedTable('records', {
  id: types.Text('id'),
  email: types.TextEq('email'),
  name: types.TextSearch('name'),
  metadata: types.Json('metadata'),
})

// ============ Mock Factories ============

/**
 * Creates a lock-context input for `.withLockContext()`.
 *
 * Since protect-ffi 0.25 dropped the per-operation CTS token, a lock context
 * is just an identity-claim spec — `.withLockContext()` accepts this plain
 * object directly (no `LockContext` instance or `identify()` call needed).
 */
export function createMockLockContext(overrides?: {
  identityClaim?: string[]
}) {
  return { identityClaim: overrides?.identityClaim ?? ['sub'] }
}

// ============ Test Helpers ============

/**
 * Whether live CipherStash credentials are present in the environment.
 */
export const hasLiveCredentials = Boolean(
  process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)

/**
 * Gate for suites that call the real CipherStash service.
 *
 * Locally, skip: without credentials `Encryption()` throws in `beforeAll`, and
 * vitest reports that as "Failed Suites 1 / Tests N skipped" — indistinguishable
 * from ordinary credential gating. That ambiguity is how #829's 21 stale EQL v2
 * assertions got attributed to missing credentials and reached CI.
 *
 * In CI, do NOT skip: missing credentials must fail the build. A plain
 * `skipIf(!hasLiveCredentials)` would be worse than the status quo — credential
 * rot would leave these suites covering nothing while CI stayed green.
 */
export const skipWithoutLiveCredentials = !hasLiveCredentials && !process.env.CI

/**
 * Unwraps a Result type, throwing an error if it's a failure.
 * Use this to simplify test assertions when you expect success.
 */
export function unwrapResult<T>(result: {
  data?: T
  failure?: { message: string }
}): T {
  if (result.failure) {
    throw new Error(result.failure.message)
  }
  return result.data as T
}

/**
 * Asserts that a result is a failure with optional message and type matching
 */
export function expectFailure(
  result: { failure?: { message: string; type?: string } },
  messagePattern?: string | RegExp,
  expectedType?: string,
) {
  expect(result.failure).toBeDefined()
  if (messagePattern) {
    if (typeof messagePattern === 'string') {
      expect(result.failure?.message).toContain(messagePattern)
    } else {
      expect(result.failure?.message).toMatch(messagePattern)
    }
  }
  if (expectedType) {
    expect(result.failure?.type).toBe(expectedType)
  }
}
