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
  // The model / bulk-model path funnels through `encryptBulk`. Return one
  // ciphertext per plaintext so the accept-case reconstruction succeeds.
  encryptBulk: vi.fn(
    async (_client: unknown, { plaintexts }: { plaintexts: unknown[] }) =>
      plaintexts.map(() => ({ v: 2, c: 'ciphertext' })),
  ),
  decrypt: vi.fn(async () => 'decrypted'),
}))

import * as ffi from '@cipherstash/protect-ffi'

const users = encryptedTable('users', {
  score: encryptedColumn('score').dataType('number').equality().orderAndRange(),
})

const usersV3 = encryptedTableV3('users_v3', {
  score: types.IntegerOrd('score'),
  big: types.BigintOrd('big'),
})

// biome-ignore lint/suspicious/noExplicitAny: test helper reads the Result union
const failure = (result: any) => result.failure

let clientV2: Awaited<ReturnType<typeof Encryption>>
let clientV3: Awaited<ReturnType<typeof Encryption>>

beforeEach(async () => {
  vi.clearAllMocks()
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  // One client per wire format: `Encryption` rejects mixed v2 + v3 schema
  // sets (one client emits exactly one wire format), so the two schema
  // styles get their own clients and the suites below pick the right one.
  clientV2 = await Encryption({ schemas: [users] })
  clientV3 = await Encryption({ schemas: [usersV3] })
})

const clientFor = (variant: 'v2' | 'v3') =>
  variant === 'v2' ? clientV2 : clientV3

describe.each([
  ['v2', { column: users.score, table: users }],
  ['v3', { column: usersV3.score, table: usersV3 }],
] as const)('encrypt with lock context rejects non-finite numbers (%s domain)', (variant, target) => {
  it('rejects NaN and never reaches the FFI', async () => {
    const result = await clientFor(variant)
      .encrypt(Number.NaN, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain('Cannot encrypt NaN value')
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })

  it('rejects +Infinity and never reaches the FFI', async () => {
    const result = await clientFor(variant)
      .encrypt(Number.POSITIVE_INFINITY, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain('Cannot encrypt Infinity value')
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })

  it('rejects -Infinity and never reaches the FFI', async () => {
    const result = await clientFor(variant)
      .encrypt(Number.NEGATIVE_INFINITY, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain('Cannot encrypt Infinity value')
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })

  it('accepts a finite number and forwards it to the FFI', async () => {
    // Positive control: proves the guards above reject *because* of the value,
    // not because the lock-context path is broken for all numbers.
    const result = await clientFor(variant)
      .encrypt(42, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeUndefined()
    expect(vi.mocked(ffi.encrypt)).toHaveBeenCalledTimes(1)
    const opts = vi.mocked(ffi.encrypt).mock.calls[0][1]
    expect(opts.plaintext).toBe(42)
  })
})

// The `bigint` analog of the NaN/±Infinity guard above. `bigint` domains map to
// Postgres `int8`, so a plaintext outside the signed 64-bit range cannot be
// stored and must be rejected. protect-ffi 0.28 ALSO bounds-checks (its
// `encodeBigIntPlaintext` throws a `RangeError`), but the SDK guard rejects
// earlier — before the network call — with a typed `EncryptionError`/Result,
// so it is kept as defense-in-depth. The live matrix suite exercises the same
// rejection over the network (`errorSamples`, secret-gated); these run in CI
// without credentials. Both the direct and lock-context encrypt arms funnel
// through the shared `assertValidNumericValue`, so both are covered.
describe('encrypt rejects out-of-range bigint (i64 bounds)', () => {
  const target = { column: usersV3.big, table: usersV3 }
  const INT64_MAX = 9223372036854775807n
  const INT64_MIN = -9223372036854775808n

  it.each([
    ['i64::MAX', INT64_MAX],
    ['i64::MIN', INT64_MIN],
    ['zero', 0n],
    ['a negative', -42n],
  ] as const)('accepts in-range bigint %s and forwards it to the FFI', async (_label, value) => {
    const result = await clientV3.encrypt(value, target)

    expect(failure(result)).toBeUndefined()
    expect(vi.mocked(ffi.encrypt)).toHaveBeenCalledTimes(1)
    expect(vi.mocked(ffi.encrypt).mock.calls[0][1].plaintext).toBe(value)
  })

  it.each([
    ['2^63 (i64::MAX + 1)', 9223372036854775808n],
    ['-(2^63) - 1 (i64::MIN - 1)', -9223372036854775809n],
  ] as const)('rejects out-of-range bigint %s and never reaches the FFI', async (_label, value) => {
    const result = await clientV3.encrypt(value, target)

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain(
      'Cannot encrypt bigint value out of int64 range',
    )
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })

  it('rejects out-of-range bigint on the lock-context arm too', async () => {
    const result = await clientV3
      .encrypt(9223372036854775808n, target)
      .withLockContext(new LockContext())

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain(
      'Cannot encrypt bigint value out of int64 range',
    )
    expect(vi.mocked(ffi.encrypt)).not.toHaveBeenCalled()
  })
})

// The model / bulk-model encrypt path builds the FFI payload directly and does
// NOT flow through the single-value `encrypt` guard, so it validates per field
// in the shared preparers (`prepareFieldsForEncryption` /
// `prepareBulkModelsForOperation`). Prove an out-of-range bigint field is
// rejected there — before `encryptBulk` — on both `encryptModel` and
// `bulkEncryptModels`, and that an in-range bigint still reaches the FFI.
describe('model / bulk encrypt guard out-of-range bigint fields', () => {
  const OUT_OF_RANGE = 9223372036854775808n // i64::MAX + 1

  it('encryptModel rejects an out-of-range bigint field and never reaches the FFI', async () => {
    const result = await clientV3.encryptModel({ big: OUT_OF_RANGE }, usersV3)

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain(
      'Cannot encrypt bigint value out of int64 range',
    )
    expect(vi.mocked(ffi.encryptBulk)).not.toHaveBeenCalled()
  })

  it('bulkEncryptModels rejects an out-of-range bigint field and never reaches the FFI', async () => {
    const result = await clientV3.bulkEncryptModels(
      [{ big: OUT_OF_RANGE }],
      usersV3,
    )

    expect(failure(result)).toBeDefined()
    expect(failure(result)?.message).toContain(
      'Cannot encrypt bigint value out of int64 range',
    )
    expect(vi.mocked(ffi.encryptBulk)).not.toHaveBeenCalled()
  })

  it('encryptModel forwards an in-range bigint field to the FFI', async () => {
    // Positive control: proves the rejections above are value-driven, not a
    // model path that rejects every bigint.
    const result = await clientV3.encryptModel({ big: 42n }, usersV3)

    expect(failure(result)).toBeUndefined()
    expect(vi.mocked(ffi.encryptBulk)).toHaveBeenCalledTimes(1)
    expect(
      vi.mocked(ffi.encryptBulk).mock.calls[0][1].plaintexts[0].plaintext,
    ).toBe(42n)
  })
})
