/**
 * Live identity-aware coverage for the v3 typed client: a lock-context
 * encrypt→decrypt round-trip through the MODEL path, plus audit metadata.
 *
 * Kept separate from `matrix-lock-context.test.ts`, which mocks
 * `@cipherstash/protect-ffi` file-wide — a mock would neutralize a "live"
 * assertion. No mock here: it federates a freshly-minted Clerk M2M JWT into a
 * CTS token via `OidcFederationStrategy` and binds the lock context to `sub`
 * (resolved by ZeroKMS from the token — here, the Clerk machine identity).
 *
 * Runs in CI on the Drizzle integration job — `integration/identity/**` is in
 * its `CS_IT_SUITE` globs. Like every integration suite it THROWS rather than
 * skips when unconfigured: `clerkJwtProvider()` requires `CLERK_MACHINE_TOKEN`.
 */
import { OidcFederationStrategy } from '@cipherstash/auth'
import { unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3, encryptedTable, types } from '@/encryption/v3'
import { clerkJwtProvider } from '../helpers/clerk'

const users = encryptedTable('v3_identity_live_users', {
  email: types.TextEq('email'),
})

const LOCK = { identityClaim: ['sub'] }

describe('v3 typed client identity-aware operations (live)', () => {
  let client: Awaited<ReturnType<typeof EncryptionV3<[typeof users]>>>

  beforeAll(async () => {
    const crn = process.env.CS_WORKSPACE_CRN
    if (!crn) {
      throw new Error('CS_WORKSPACE_CRN must be set for identity tests')
    }
    // `create()` returns a `Result`; unwrap to the strategy `config.authStrategy`
    // expects. `clerkJwtProvider()` asserts CLERK_MACHINE_TOKEN and re-mints on
    // every re-federation.
    const federation = OidcFederationStrategy.create(crn, clerkJwtProvider())
    if (federation.failure) {
      throw new Error(`[federation]: ${federation.failure.message}`)
    }
    client = await EncryptionV3({
      schemas: [users],
      config: { authStrategy: federation.data },
    })
  }, 30000)

  it('round-trips a model with a lock context (encrypt + decrypt bound to identity)', async () => {
    const encrypted = unwrapResult(
      await client
        .encryptModel({ email: 'ada@example.com' }, users)
        .withLockContext(LOCK),
    )
    expect(encrypted.email).toHaveProperty('c')

    // decryptModel takes the lock context as a positional 3rd arg
    // (`LockContextInput` = `LockContext | { identityClaim }`).
    const decrypted = unwrapResult(
      await client.decryptModel(encrypted, users, LOCK),
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
