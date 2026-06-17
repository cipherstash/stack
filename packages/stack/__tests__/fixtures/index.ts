import { expect, vi } from 'vitest'
import { encryptedColumn, encryptedTable } from '@/schema'

// ============ Schema Fixtures ============

/**
 * Users table with multiple index types for testing
 */
export const users = encryptedTable('users', {
  email: encryptedColumn('email').equality(),
  bio: encryptedColumn('bio').freeTextSearch(),
  age: encryptedColumn('age').dataType('number').orderAndRange(),
})

/**
 * Articles table with only freeTextSearch (for auto-inference test)
 */
export const articles = encryptedTable('articles', {
  content: encryptedColumn('content').freeTextSearch(),
})

/**
 * Products table with only orderAndRange (for auto-inference test)
 */
export const products = encryptedTable('products', {
  price: encryptedColumn('price').dataType('number').orderAndRange(),
})

/**
 * Metadata table with no indexes (for validation error test)
 */
export const metadata = encryptedTable('metadata', {
  raw: encryptedColumn('raw'),
})

/**
 * Documents table with searchable JSON column (for STE Vec queries)
 */
export const jsonbSchema = encryptedTable('documents', {
  id: encryptedColumn('id'),
  metadata: encryptedColumn('metadata').searchableJson(),
})

/**
 * Schema fixture with mixed column types including JSON.
 */
export const mixedSchema = encryptedTable('records', {
  id: encryptedColumn('id'),
  email: encryptedColumn('email').equality(),
  name: encryptedColumn('name').freeTextSearch(),
  metadata: encryptedColumn('metadata').searchableJson(),
})

// ============ Mock Factories ============

/**
 * Creates a mock LockContext with successful response
 */
export function createMockLockContext(overrides?: {
  accessToken?: string
  expiry?: number
  identityClaim?: string[]
}) {
  return {
    getLockContext: vi.fn().mockResolvedValue({
      data: {
        ctsToken: {
          accessToken: overrides?.accessToken ?? 'mock-token',
          expiry: overrides?.expiry ?? Date.now() + 3600000,
        },
        context: {
          identityClaim: overrides?.identityClaim ?? ['sub'],
        },
      },
    }),
  }
}

/**
 * Creates a mock LockContext with explicit null context (simulates runtime edge case)
 */
export function createMockLockContextWithNullContext() {
  return {
    getLockContext: vi.fn().mockResolvedValue({
      data: {
        ctsToken: {
          accessToken: 'mock-token',
          expiry: Date.now() + 3600000,
        },
        context: null, // Explicit null - simulating runtime edge case
      },
    }),
  }
}

/**
 * Creates a mock LockContext that returns a failure
 */
export function createFailingMockLockContext(
  errorType: string,
  message: string,
) {
  return {
    getLockContext: vi.fn().mockResolvedValue({
      failure: { type: errorType, message },
    }),
  }
}

// ============ Test Helpers ============

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
