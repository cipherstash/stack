/**
 * Runtime proof that audit metadata attached to the typed EQL v3 client's
 * `decryptModel` / `bulkDecryptModels` reaches ZeroKMS — the core half of
 * acceptance #2b. Before PR 3 the typed client `await`ed the underlying decrypt
 * and mapped the value, which collapsed the chain and dropped `.audit()`; the
 * `MappedDecryptOperation` wrapper restores it.
 *
 * The metadata surfaces as `unverifiedContext` on the mocked protect-ffi
 * `decryptBulk` call. Both chaining orders are covered (Risk R3):
 * `.audit().withLockContext()` and `.withLockContext().audit()` must each
 * forward the metadata (and the lock context's identity claim).
 *
 * Credential-free: protect-ffi is mocked, so there is no ZeroKMS round-trip.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Encryption } from '@/index'

// A protect-ffi-shaped encrypted payload so the SDK's `isEncryptedPayload`
// check detects the model field as encrypted and routes it to `decryptBulk`.
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
// Imported after the mock so the v3 table builder is available; `Encryption`
// returns the typed client for an all-v3 schema set.
import { encryptedTable, types } from '@/encryption/v3'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
})

const IDENTITY_CLAIM = { identityClaim: ['sub'] }

// biome-ignore lint/suspicious/noExplicitAny: test helper unwraps Result
function unwrap(result: any) {
  if (result.failure) {
    throw new Error(`operation failed: ${result.failure.message}`)
  }
  return result.data
}

/** Options the FFI decrypt was last called with (second arg). */
// biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
const lastDecryptOpts = () => (ffi.decryptBulk as any).mock.calls.at(-1)[1]

/** The lock context is carried per-ciphertext, not on the top-level opts. */
const lastCiphertextLockContext = () =>
  lastDecryptOpts().ciphertexts[0]?.lockContext

let client: Awaited<ReturnType<typeof Encryption<readonly [typeof users]>>>

beforeEach(async () => {
  vi.clearAllMocks()
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  client = await Encryption({ schemas: [users] })
})

describe('typed v3 client: audit metadata forwards through decryptModel', () => {
  it('forwards .audit({ metadata }) as unverifiedContext (no lock context)', async () => {
    unwrap(
      await client
        .decryptModel({ email: enc() }, users)
        .audit({ metadata: { sub: 'u1' } }),
    )

    expect(ffi.decryptBulk).toHaveBeenCalledTimes(1)
    expect(lastDecryptOpts().unverifiedContext).toEqual({ sub: 'u1' })
  })

  it('forwards metadata AND identity claim with .audit().withLockContext()', async () => {
    unwrap(
      await client
        .decryptModel({ email: enc() }, users)
        .audit({ metadata: { m: 1 } })
        .withLockContext(IDENTITY_CLAIM),
    )

    expect(ffi.decryptBulk).toHaveBeenCalledTimes(1)
    const opts = lastDecryptOpts()
    expect(opts.unverifiedContext).toEqual({ m: 1 })
    expect(lastCiphertextLockContext()).toEqual(IDENTITY_CLAIM)
  })

  it('forwards metadata AND identity claim with .withLockContext().audit()', async () => {
    unwrap(
      await client
        .decryptModel({ email: enc() }, users)
        .withLockContext(IDENTITY_CLAIM)
        .audit({ metadata: { m: 2 } }),
    )

    expect(ffi.decryptBulk).toHaveBeenCalledTimes(1)
    const opts = lastDecryptOpts()
    expect(opts.unverifiedContext).toEqual({ m: 2 })
    expect(lastCiphertextLockContext()).toEqual(IDENTITY_CLAIM)
  })

  it('forwards metadata via the lockContext argument (no chaining)', async () => {
    unwrap(
      await client
        .decryptModel({ email: enc() }, users, IDENTITY_CLAIM)
        .audit({ metadata: { m: 3 } }),
    )

    expect(ffi.decryptBulk).toHaveBeenCalledTimes(1)
    const opts = lastDecryptOpts()
    expect(opts.unverifiedContext).toEqual({ m: 3 })
    expect(lastCiphertextLockContext()).toEqual(IDENTITY_CLAIM)
  })

  it('forwards .audit({ metadata }) on bulkDecryptModels', async () => {
    unwrap(
      await client
        .bulkDecryptModels([{ email: enc() }], users)
        .audit({ metadata: { b: 4 } }),
    )

    expect(ffi.decryptBulk).toHaveBeenCalledTimes(1)
    expect(lastDecryptOpts().unverifiedContext).toEqual({ b: 4 })
  })
})
