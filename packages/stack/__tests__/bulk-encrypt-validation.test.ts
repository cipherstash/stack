import { describe, expect, it } from 'vitest'
import {
  BulkEncryptOperation,
  BulkEncryptOperationWithLockContext,
} from '@/encryption/operations/bulk-encrypt'
import type {
  BuildableColumn,
  BuildableTable,
  BulkEncryptPayload,
  Client,
} from '@/types'

/**
 * `EncryptOperation` rejects NaN / ±Infinity / out-of-int64 `bigint` values
 * client-side, before they reach protect-ffi (whose behaviour on such a value
 * is unobservable — see `helpers/validation.ts`). `BulkEncryptOperation` must
 * enforce the same contract: any caller that batches instead of looping — the
 * v3 Drizzle `inArray`, for one — otherwise silently loses the guard.
 *
 * The stub client is never reached: validation must throw first. If a case
 * here ever calls into protect-ffi, the fake client surfaces it as a different
 * error than the one asserted.
 */
const client = {} as Client

const column: BuildableColumn = {
  getName: () => 'age',
  build: () => ({}) as never,
}

const table: BuildableTable = {
  tableName: 'users',
  build: () => ({ tableName: 'users', columns: {} }),
}

const payload = (...values: unknown[]): BulkEncryptPayload =>
  values.map((plaintext) => ({ plaintext })) as BulkEncryptPayload

const lockContext = {
  ctsToken: { accessToken: 'token' },
} as never

describe('BulkEncryptOperation numeric validation', () => {
  it.each([
    [Number.NaN, 'Cannot encrypt NaN value'],
    [Number.POSITIVE_INFINITY, 'Cannot encrypt Infinity value'],
    [Number.NEGATIVE_INFINITY, 'Cannot encrypt Infinity value'],
    [2n ** 70n, 'Cannot encrypt bigint value out of int64 range'],
    [-(2n ** 70n), 'Cannot encrypt bigint value out of int64 range'],
  ])('rejects %s before reaching the FFI', async (value, message) => {
    const op = new BulkEncryptOperation(client, payload(value), {
      column,
      table,
    })

    const result = await op.execute()

    expect(result.failure?.message).toContain(message)
  })

  it('rejects an invalid value anywhere in the list, not just the first', async () => {
    const op = new BulkEncryptOperation(client, payload(30, 42, Number.NaN), {
      column,
      table,
    })

    const result = await op.execute()

    expect(result.failure?.message).toContain('Cannot encrypt NaN value')
  })

  it('still passes null entries through without tripping validation', async () => {
    const op = new BulkEncryptOperation(client, [{ plaintext: null }], {
      column,
      table,
    })

    const result = await op.execute()

    expect(result.failure).toBeUndefined()
    expect(result.data).toEqual([{ id: undefined, data: null }])
  })

  it('accepts in-range bigints at the int64 boundary', async () => {
    const op = new BulkEncryptOperation(client, payload(9223372036854775807n), {
      column,
      table,
    })

    const result = await op.execute()

    // Validation passes, so the stub client is reached — proving the boundary
    // value was NOT rejected by the numeric guard.
    expect(result.failure?.message).not.toContain('out of int64 range')
  })

  it('enforces the same guard on the lock-context variant', async () => {
    const op = new BulkEncryptOperationWithLockContext(
      new BulkEncryptOperation(client, payload(Number.NaN), { column, table }),
      lockContext,
    )

    const result = await op.execute()

    expect(result.failure?.message).toContain('Cannot encrypt NaN value')
  })
})
