/**
 * Live identity-aware coverage for the v3 typed client: lock-context round-trips
 * and audit metadata. Kept separate from `matrix-lock-context.test.ts` because
 * that file mocks `@cipherstash/protect-ffi` file-wide — a mock would neutralize
 * a "live" assertion. No mock here: these hit a real CipherStash workspace and
 * soft-skip when credentials (and, for lock context, `USER_JWT`) are absent,
 * mirroring the v2 `audit.test.ts` / lock-context pattern.
 */
import { requireIntegrationEnv, unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3, encryptedTable, types } from '@/encryption/v3'
import { LockContext } from '@/identity'

const users = encryptedTable('v3_identity_live_users', {
  email: types.TextEq('email'),
})

describe('v3 typed client identity-aware operations (live)', () => {
  let client: Awaited<ReturnType<typeof EncryptionV3<[typeof users]>>>

  beforeAll(async () => {
    requireIntegrationEnv(['userjwt'])
    client = await EncryptionV3({ schemas: [users] })
  }, 30000)

  it('round-trips a model with a lock context (encrypt + decrypt bound to identity)', async () => {
    const userJwt = process.env.USER_JWT as string

    const lc = new LockContext()
    const lockContext = await lc.identify(userJwt)
    if (lockContext.failure) {
      throw new Error(`[protect]: ${lockContext.failure.message}`)
    }

    const encrypted = unwrapResult(
      await client
        .encryptModel({ email: 'ada@example.com' }, users)
        .withLockContext(lockContext.data),
    )
    expect(encrypted.email).toHaveProperty('c')

    // decryptModel takes the lock context as a positional 3rd arg.
    const decrypted = unwrapResult(
      await client.decryptModel(encrypted, users, lockContext.data),
    )
    expect(decrypted.email).toBe('ada@example.com')
  }, 30000)

  it('accepts .audit({ metadata }) on the encrypt path and still round-trips', async () => {
    const encrypted = unwrapResult(
      await client
        .encrypt('secret@example.com', { table: users, column: users.email })
        .audit({ metadata: { sub: 'toby@cipherstash.com', type: 'encrypt' } }),
    )
    expect(encrypted).toHaveProperty('c')

    const decrypted = unwrapResult(await client.decrypt(encrypted))
    expect(decrypted).toBe('secret@example.com')
  }, 30000)
})
