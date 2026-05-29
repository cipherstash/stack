/**
 * Offline wiring tests for the lock-context path.
 *
 * protect-ffi 0.25 removed the per-operation `serviceToken` option — the
 * CTS token is no longer forwarded; lock contexts travel as
 * `lockContext.identityClaim` only. The live `lock-context.test.ts`
 * exercises a real CTS round-trip but skips without a `USER_JWT`, so it
 * can't guard this wiring in CI. These tests mock `@cipherstash/protect-ffi`
 * and assert, for every operation, that:
 *   1. the lock context's `identityClaim` reaches protect-ffi, and
 *   2. no `serviceToken` is ever passed (the removed field must not creep
 *      back in).
 */
import { Encryption } from '@/index'
import { LockContext } from '@/identity'
import { encryptedColumn, encryptedTable } from '@/schema'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// A protect-ffi-shaped encrypted payload (passes the SDK's
// `isEncryptedPayload` check so model decrypt detects encrypted fields).
const enc = () => ({ v: 2, i: { t: 'users', c: 'email' }, c: 'ciphertext' })

vi.mock('@cipherstash/protect-ffi', () => ({
  newClient: vi.fn(async () => ({ __mock: 'client' })),
  encrypt: vi.fn(async () => enc()),
  decrypt: vi.fn(async () => 'decrypted'),
  encryptBulk: vi.fn(async (_c: unknown, opts: { plaintexts: unknown[] }) =>
    opts.plaintexts.map(enc),
  ),
  decryptBulk: vi.fn(async (_c: unknown, opts: { ciphertexts: unknown[] }) =>
    opts.ciphertexts.map(() => 'decrypted'),
  ),
  decryptBulkFallible: vi.fn(
    async (_c: unknown, opts: { ciphertexts: unknown[] }) =>
      opts.ciphertexts.map(() => ({ data: 'decrypted' })),
  ),
  encryptQuery: vi.fn(async () => enc()),
  encryptQueryBulk: vi.fn(async (_c: unknown, opts: { queries: unknown[] }) =>
    opts.queries.map(enc),
  ),
}))

import * as ffi from '@cipherstash/protect-ffi'

const users = encryptedTable('users', {
  email: encryptedColumn('email').equality(),
})

const IDENTITY_CLAIM = { identityClaim: ['sub'] }

// Build a lock context without a network round-trip: a pre-supplied CTS
// token short-circuits `identify()`, and the default context is
// `{ identityClaim: ['sub'] }`.
const lockCtx = () =>
  new LockContext({
    ctsToken: { accessToken: 'test-cts-token', expiry: 9_999_999_999 },
  })

/** Deep scan for a `serviceToken` key anywhere in a value. */
function hasServiceToken(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasServiceToken)
  if (value && typeof value === 'object') {
    if ('serviceToken' in value) return true
    return Object.values(value).some(hasServiceToken)
  }
  return false
}

// biome-ignore lint/suspicious/noExplicitAny: test helper unwraps Result
function unwrap(result: any) {
  if (result.failure) {
    throw new Error(`operation failed: ${result.failure.message}`)
  }
  return result.data
}

/** Options the operation was last called with (second arg to the ffi fn). */
// biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
const lastOpts = (fn: any) => fn.mock.calls.at(-1)[1]

let client: Awaited<ReturnType<typeof Encryption>>

beforeEach(async () => {
  vi.clearAllMocks()
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  client = await Encryption({ schemas: [users] })
})

describe('lock-context wiring: identityClaim forwarded, serviceToken never sent', () => {
  it('encrypt forwards lockContext and omits serviceToken', async () => {
    unwrap(
      await client
        .encrypt('alice@example.com', { column: users.email, table: users })
        .withLockContext(lockCtx()),
    )

    const opts = lastOpts(ffi.encrypt)
    expect(opts.lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('encrypt without a lock context sends neither lockContext nor serviceToken', async () => {
    unwrap(
      await client.encrypt('alice@example.com', {
        column: users.email,
        table: users,
      }),
    )

    const opts = lastOpts(ffi.encrypt)
    expect(opts.lockContext).toBeUndefined()
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('decrypt forwards lockContext and omits serviceToken', async () => {
    unwrap(await client.decrypt(enc()).withLockContext(lockCtx()))

    const opts = lastOpts(ffi.decrypt)
    expect(opts.lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('bulkEncrypt forwards per-payload lockContext and omits serviceToken', async () => {
    unwrap(
      await client
        .bulkEncrypt([{ id: '1', plaintext: 'alice@example.com' }], {
          column: users.email,
          table: users,
        })
        .withLockContext(lockCtx()),
    )

    const opts = lastOpts(ffi.encryptBulk)
    expect(opts.plaintexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('bulkDecrypt forwards per-payload lockContext and omits serviceToken', async () => {
    unwrap(
      await client
        .bulkDecrypt([{ id: '1', data: enc() }])
        .withLockContext(lockCtx()),
    )

    const opts = lastOpts(ffi.decryptBulkFallible)
    expect(opts.ciphertexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('encryptQuery (single) forwards lockContext and omits serviceToken', async () => {
    unwrap(
      await client
        .encryptQuery('alice@example.com', {
          column: users.email,
          table: users,
        })
        .withLockContext(lockCtx()),
    )

    const opts = lastOpts(ffi.encryptQuery)
    expect(opts.lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('encryptQuery (batch) forwards per-query lockContext and omits serviceToken', async () => {
    unwrap(
      await client
        .encryptQuery([
          { value: 'alice@example.com', column: users.email, table: users },
        ])
        .withLockContext(lockCtx()),
    )

    const opts = lastOpts(ffi.encryptQueryBulk)
    expect(opts.queries[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('encryptModel forwards per-payload lockContext and omits serviceToken', async () => {
    unwrap(
      await client
        .encryptModel({ id: '1', email: 'alice@example.com' }, users)
        .withLockContext(lockCtx()),
    )

    const opts = lastOpts(ffi.encryptBulk)
    expect(opts.plaintexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('decryptModel forwards per-payload lockContext and omits serviceToken', async () => {
    unwrap(
      await client
        .decryptModel({ id: '1', email: enc() })
        .withLockContext(lockCtx()),
    )

    const opts = lastOpts(ffi.decryptBulk)
    expect(opts.ciphertexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })
})
