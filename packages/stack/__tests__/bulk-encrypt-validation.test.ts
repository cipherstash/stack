import { describe, expect, it } from 'vitest'
import type { CryptoBackend } from '@/encryption/backend'
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

// Validation must reject BEFORE the FFI is reached. Injecting a backend that
// throws on contact makes that a positive assertion rather than something
// inferred from the error message (#798).
const forbiddenBackend = new Proxy({} as CryptoBackend, {
  get: (_target, name) => () => {
    throw new Error(`FFI ${String(name)}() must not be reached by validation`)
  },
})

/**
 * A backend that records what reached the FFI and returns one ciphertext per
 * input.
 *
 * For the cases where validation is expected to PASS, `forbiddenBackend` is the
 * wrong tool: it makes the operation fail, so the only thing left to assert is
 * that the message differs from the rejection message — which would also hold
 * if the guard broke and rejected with different wording, or if the call failed
 * for an unrelated reason. Recording the call lets those tests assert what they
 * actually mean: the value got through, and got through unchanged.
 */
const recordingBackend = () => {
  const calls: { plaintext: unknown }[][] = []
  const backend = {
    encryptBulk: async (
      _client: unknown,
      opts: { plaintexts: { plaintext: unknown }[] },
    ) => {
      calls.push(opts.plaintexts)
      return opts.plaintexts.map((_, i) => ({ c: `ct-${i}` }))
    },
  } as unknown as CryptoBackend
  return { backend, calls }
}

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
    const op = new BulkEncryptOperation(
      client,
      forbiddenBackend,
      payload(value),
      {
        column,
        table,
      },
    )

    const result = await op.execute()

    expect(result.failure?.message).toContain(message)
  })

  it('rejects an invalid value anywhere in the list, not just the first', async () => {
    const op = new BulkEncryptOperation(
      client,
      forbiddenBackend,
      payload(30, 42, Number.NaN),
      {
        column,
        table,
      },
    )

    const result = await op.execute()

    expect(result.failure?.message).toContain('Cannot encrypt NaN value')
  })

  it('still passes null entries through without tripping validation', async () => {
    const op = new BulkEncryptOperation(
      client,
      forbiddenBackend,
      [{ plaintext: null }],
      {
        column,
        table,
      },
    )

    const result = await op.execute()

    expect(result.failure).toBeUndefined()
    expect(result.data).toEqual([{ id: undefined, data: null }])
  })

  it('accepts in-range bigints at the int64 boundary', async () => {
    const { backend, calls } = recordingBackend()
    const boundary = 9223372036854775807n

    const op = new BulkEncryptOperation(client, backend, payload(boundary), {
      column,
      table,
    })

    const result = await op.execute()

    // Three separate claims, none of which the old
    // `expect(failure?.message).not.toContain('out of int64 range')` could
    // make: the guard let it through, the FFI was reached, and the value
    // arrived intact rather than coerced on the way.
    expect(result.failure).toBeUndefined()
    expect(calls).toEqual([
      [
        {
          id: undefined,
          plaintext: boundary,
          column: 'age',
          table: 'users',
        },
      ],
    ])
    expect(result.data).toEqual([{ id: undefined, data: { c: 'ct-0' } }])
  })

  it('enforces the same guard on the lock-context variant', async () => {
    const op = new BulkEncryptOperationWithLockContext(
      new BulkEncryptOperation(client, forbiddenBackend, payload(Number.NaN), {
        column,
        table,
      }),
      lockContext,
    )

    const result = await op.execute()

    expect(result.failure?.message).toContain('Cannot encrypt NaN value')
  })
})
