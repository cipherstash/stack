/**
 * Offline guard tests for the lock-context encrypt path.
 *
 * `EncryptOperationWithLockContext.execute()` re-applies the NaN / Infinity
 * runtime guards that the non-lock `EncryptOperation.execute()` has. The
 * non-lock guards are exercised by the live `number-protect.test.ts` (its
 * `beforeAll` builds a real client), but the lock-context arm — reached via
 * `encrypt(value).withLockContext(...)` — had no coverage in any suite. These
 * tests mock `@cipherstash/protect-ffi` so they run in CI without credentials
 * and assert that:
 *   1. NaN / +Infinity / -Infinity are rejected as failures with the same
 *      messages as the non-lock path, and
 *   2. the guard short-circuits *before* the FFI encrypt call (a leaked NaN
 *      must never reach the ciphertext boundary).
 *
 * Every case runs against both a v2 fluent-builder column and a v3 domain
 * column: the guards live on the shared `EncryptOperationWithLockContext`, so
 * both schema styles must take the identical short-circuit path.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { encryptedTable as encryptedTableV3, types } from '@/eql/v3'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'

vi.mock('@cipherstash/protect-ffi', () => ({
  // `getErrorCode` does `error instanceof ProtectError` on the failure path,
  // so the mock must export the class even though the guards throw plain Errors.
  ProtectError: class ProtectError extends Error {},
  newClient: vi.fn(async () => ({ __mock: 'client' })),
  encrypt: vi.fn(async () => ({ v: 2, c: 'ciphertext' })),
  decrypt: vi.fn(async () => 'decrypted'),
}))

import * as ffi from '@cipherstash/protect-ffi'

const users = encryptedTable('users', {
  score: encryptedColumn('score').dataType('number').equality().orderAndRange(),
})

const usersV3 = encryptedTableV3('users_v3', {
  score: types.Int4Ord('score'),
})

// biome-ignore lint/suspicious/noExplicitAny: test helper reads the Result union
const failure = (result: any) => result.failure

let client: Awaited<ReturnType<typeof Encryption>>

beforeEach(async () => {
  vi.clearAllMocks()
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  client = await Encryption({ schemas: [users, usersV3] })
})

describe.each([
  ['v2 fluent builder', { column: users.score, table: users }],
  ['v3 domain type', { column: usersV3.score, table: usersV3 }],
] as const)('encrypt with lock context rejects non-finite numbers (%s)', (_variant, target) => {
  it('rejects NaN and never reaches the FFI', async () => {
    const result = await client
      .encrypt(Number.NaN, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain('Cannot encrypt NaN value')
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })

  it('rejects +Infinity and never reaches the FFI', async () => {
    const result = await client
      .encrypt(Number.POSITIVE_INFINITY, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain('Cannot encrypt Infinity value')
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })

  it('rejects -Infinity and never reaches the FFI', async () => {
    const result = await client
      .encrypt(Number.NEGATIVE_INFINITY, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain('Cannot encrypt Infinity value')
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })

  it('accepts a finite number and forwards it to the FFI', async () => {
    // Positive control: proves the guards above reject *because* of the value,
    // not because the lock-context path is broken for all numbers.
    const result = await client
      .encrypt(42, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeUndefined()
    expect(vi.mocked(ffi.encrypt)).toHaveBeenCalledTimes(1)
    const opts = vi.mocked(ffi.encrypt).mock.calls[0][1]
    expect(opts.plaintext).toBe(42)
  })
})
