/**
 * Offline lock-context wiring for the v3 TYPED client.
 *
 * `lock-context-wiring.test.ts` proves the base (v2) client forwards
 * `identityClaim` and never sends a `serviceToken`. This file proves the same
 * for the v3 typed client — and specifically covers the one shape the v2 wiring
 * cannot: `typedClient.decryptModel(model, table, lockContext)` takes the lock
 * context as a POSITIONAL arg (not a `.withLockContext()` chain), and must still
 * thread `identityClaim` through to the FFI. Mocks `@cipherstash/protect-ffi` so
 * it runs deterministically in CI without credentials.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'

// A protect-ffi-shaped encrypted payload (passes `isEncryptedPayload`).
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
import { encryptedTable, typedClient, types } from '@/encryption/v3'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
})

const IDENTITY_CLAIM = { identityClaim: ['sub'] }
const lockCtx = () => new LockContext()

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

let typed: ReturnType<typeof typedClient>
let prevWorkspaceCrn: string | undefined

beforeEach(async () => {
  vi.clearAllMocks()
  prevWorkspaceCrn = process.env.CS_WORKSPACE_CRN
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  typed = typedClient(await Encryption({ schemas: [users] as never }), users)
})

afterEach(() => {
  // Restore the prior value so this suite doesn't leak env state into
  // other Vitest suites sharing the worker.
  if (prevWorkspaceCrn === undefined) {
    delete process.env.CS_WORKSPACE_CRN
  } else {
    process.env.CS_WORKSPACE_CRN = prevWorkspaceCrn
  }
})

describe('v3 typed client lock-context wiring', () => {
  it('encrypt().withLockContext() forwards identityClaim, no serviceToken', async () => {
    unwrap(
      await typed
        .encrypt('alice@example.com', { table: users, column: users.email })
        .withLockContext(lockCtx()),
    )
    const opts = lastOpts(ffi.encrypt)
    expect(opts.lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('encrypt().withLockContext() accepts a plain { identityClaim } object', async () => {
    unwrap(
      await typed
        .encrypt('alice@example.com', { table: users, column: users.email })
        .withLockContext({ identityClaim: ['sub'] }),
    )
    const opts = lastOpts(ffi.encrypt)
    expect(opts.lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('encryptModel().withLockContext() forwards per-payload identityClaim', async () => {
    unwrap(
      await typed
        .encryptModel({ email: 'alice@example.com' }, users)
        .withLockContext(lockCtx()),
    )
    const opts = lastOpts(ffi.encryptBulk)
    expect(opts.plaintexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  // The v3-specific path: lockContext supplied as a POSITIONAL 3rd arg, not a
  // chain. Must still reach the FFI.
  it('decryptModel(model, table, { identityClaim }) forwards identityClaim positionally', async () => {
    unwrap(
      await typed.decryptModel({ email: enc() }, users, {
        identityClaim: ['sub'],
      }),
    )
    const opts = lastOpts(ffi.decryptBulk)
    expect(opts.ciphertexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('decryptModel(model, table, lockContext) accepts a LockContext instance positionally', async () => {
    unwrap(await typed.decryptModel({ email: enc() }, users, lockCtx()))
    const opts = lastOpts(ffi.decryptBulk)
    expect(opts.ciphertexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('bulkDecryptModels(rows, table, lockContext) forwards per-row identityClaim', async () => {
    unwrap(await typed.bulkDecryptModels([{ email: enc() }], users, lockCtx()))
    const opts = lastOpts(ffi.decryptBulk)
    expect(opts.ciphertexts[0].lockContext).toEqual(IDENTITY_CLAIM)
    expect(hasServiceToken(opts)).toBe(false)
  })

  it('decryptModel WITHOUT a lock context sends neither lockContext nor serviceToken', async () => {
    unwrap(await typed.decryptModel({ email: enc() }, users))
    const opts = lastOpts(ffi.decryptBulk)
    expect(opts.ciphertexts[0].lockContext).toBeUndefined()
    expect(hasServiceToken(opts)).toBe(false)
  })
})
