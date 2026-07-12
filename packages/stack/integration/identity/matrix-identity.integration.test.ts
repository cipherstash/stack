/**
 * Live identity-aware coverage for the v3 typed client: a lock-context
 * encrypt→decrypt round-trip through the MODEL path, the negative path (a model
 * sealed under an identity must NOT decrypt without its context), plus audit
 * metadata.
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

// A genuine key-derivation denial — ZeroKMS cannot reproduce the identity-bound
// key without the context the model was sealed under — versus a transport/outage
// fault that must never be read as a denial. Mirrors the matchers the Drizzle
// lock-context suite pins to.
const KEY_DENIAL = /failed to retrieve key/i
const INFRA_FAULT =
  /ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up|timed? ?out|network error/i

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

  // NEGATIVE PATH. The round-trip above applies the SAME context on both sides,
  // so it stays green even if the model path ignored the lock context entirely.
  // This is the assertion that fails if it does: a model sealed under an identity
  // must NOT decrypt without its context. `decryptModel` reports denial as a
  // `Result.failure` rather than throwing, so read it off the result (and count
  // a throw as denial too) instead of unwrapping — a bare `unwrapResult` would
  // turn a held boundary into a thrown error and mask WHY it was denied.
  it('a model sealed with a lock context does NOT decrypt without it', async () => {
    const encrypted = unwrapResult(
      await client
        .encryptModel({ email: 'ada@example.com' }, users)
        .withLockContext(LOCK),
    )

    let denied = false
    let message = ''
    try {
      const result: { failure?: { message: string } } =
        await client.decryptModel(encrypted, users)
      denied = Boolean(result.failure)
      message = result.failure?.message ?? ''
    } catch (error) {
      denied = true
      message = (error as Error).message
    }

    expect(
      denied,
      `model decrypt must be denied without its context (got: ${message})`,
    ).toBe(true)
    // A real key-derivation denial, not an outage masquerading as one.
    expect(message).toMatch(KEY_DENIAL)
    expect(message).not.toMatch(INFRA_FAULT)
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
