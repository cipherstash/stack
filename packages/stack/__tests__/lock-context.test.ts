import 'dotenv/config'
import { OidcFederationStrategy } from '@cipherstash/auth'
import { describe, expect, it } from 'vitest'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'

/**
 * Live, identity-bound encryption round-trips (gated on `USER_JWT`).
 *
 * This exercises the strategy-based replacement for the old LockContext
 * ceremony: the client authenticates as the end user via
 * `OidcFederationStrategy` (federating their OIDC JWT into a CTS service
 * token), and the data key is bound to the user's `sub` claim with a plain
 * `.withLockContext({ identityClaim })` — no `identify()`, no CTS token
 * passed by hand. Decrypting without the same claim must fail.
 *
 * Requires `USER_JWT` plus `CS_WORKSPACE_CRN` / `CS_CLIENT_ID` / `CS_CLIENT_KEY`.
 *
 * These `skipIf` out when the credentials are absent. They must never *pass*
 * without them: an early `return` would report four green assertions that
 * never ran, which is how the `OidcFederationStrategy.create` Result-unwrap
 * bug survived here unnoticed.
 */
const LIVE = Boolean(process.env.USER_JWT && process.env.CS_WORKSPACE_CRN)
const users = encryptedTable('users', {
  email: encryptedColumn('email').freeTextSearch().equality().orderAndRange(),
  address: encryptedColumn('address').freeTextSearch(),
})

const IDENTITY_CLAIM = { identityClaim: ['sub'] }

/**
 * Build an encryption client that authenticates every ZeroKMS request as
 * the end user behind `userJwt`. `getJwt` returns the *current* JWT and is
 * re-invoked on every (re-)federation — here the value is constant.
 */
async function userClient(userJwt: string) {
  const crn = process.env.CS_WORKSPACE_CRN
  if (!crn) {
    throw new Error('CS_WORKSPACE_CRN must be set for the lock-context tests')
  }

  // `create` returns a `Result` as of `@cipherstash/auth` 0.41 — unwrap it. The
  // envelope has no `getToken()`, so forwarding it to `authStrategy` fails inside
  // the FFI.
  const strategy = OidcFederationStrategy.create(crn, () =>
    Promise.resolve(userJwt),
  )
  if (strategy.failure) {
    throw new Error(
      `Failed to construct OidcFederationStrategy (${strategy.failure.type}): ${strategy.failure.error.message}`,
    )
  }

  return Encryption({
    schemas: [users],
    config: { authStrategy: strategy.data },
  })
}

describe.skipIf(!LIVE)(
  'identity-bound encryption via OidcFederationStrategy + lock context',
  () => {
    it('should encrypt and decrypt a payload bound to the user identity', async () => {
      const userJwt = process.env.USER_JWT as string

      const protectClient = await userClient(userJwt)
      const email = 'hello@example.com'

      const ciphertext = await protectClient
        .encrypt(email, { column: users.email, table: users })
        .withLockContext(IDENTITY_CLAIM)

      if (ciphertext.failure) {
        throw new Error(`[protect]: ${ciphertext.failure.message}`)
      }

      const plaintext = await protectClient
        .decrypt(ciphertext.data)
        .withLockContext(IDENTITY_CLAIM)

      if (plaintext.failure) {
        throw new Error(`[protect]: ${plaintext.failure.message}`)
      }

      expect(plaintext.data).toEqual(email)
    }, 30000)

    it('should encrypt and decrypt a model bound to the user identity', async () => {
      const userJwt = process.env.USER_JWT as string

      const protectClient = await userClient(userJwt)
      const decryptedModel = { id: '1', email: 'plaintext' }

      const encryptedModel = await protectClient
        .encryptModel(decryptedModel, users)
        .withLockContext(IDENTITY_CLAIM)

      if (encryptedModel.failure) {
        throw new Error(`[protect]: ${encryptedModel.failure.message}`)
      }

      const decryptedResult = await protectClient
        .decryptModel(encryptedModel.data)
        .withLockContext(IDENTITY_CLAIM)

      if (decryptedResult.failure) {
        throw new Error(`[protect]: ${decryptedResult.failure.message}`)
      }

      expect(decryptedResult.data).toEqual({ id: '1', email: 'plaintext' })
    }, 30000)

    it('should encrypt with context and be unable to decrypt without it', async () => {
      const userJwt = process.env.USER_JWT as string

      const protectClient = await userClient(userJwt)
      const decryptedModel = { id: '1', email: 'plaintext' }

      const encryptedModel = await protectClient
        .encryptModel(decryptedModel, users)
        .withLockContext(IDENTITY_CLAIM)

      if (encryptedModel.failure) {
        throw new Error(`[protect]: ${encryptedModel.failure.message}`)
      }

      // Decrypting without the identity claim cannot reproduce the key tag.
      try {
        await protectClient.decryptModel(encryptedModel.data)
      } catch (error) {
        const e = error as Error
        expect(e.message.startsWith('Failed to retrieve key')).toEqual(true)
      }
    }, 30000)

    it('should bulk encrypt and decrypt models bound to the user identity', async () => {
      const userJwt = process.env.USER_JWT as string

      const protectClient = await userClient(userJwt)
      const decryptedModels = [
        { id: '1', email: 'test' },
        { id: '2', email: 'test2' },
      ]

      const encryptedModels = await protectClient
        .bulkEncryptModels(decryptedModels, users)
        .withLockContext(IDENTITY_CLAIM)

      if (encryptedModels.failure) {
        throw new Error(`[protect]: ${encryptedModels.failure.message}`)
      }

      const decryptedResult = await protectClient
        .bulkDecryptModels(encryptedModels.data)
        .withLockContext(IDENTITY_CLAIM)

      if (decryptedResult.failure) {
        throw new Error(`[protect]: ${decryptedResult.failure.message}`)
      }

      expect(decryptedResult.data).toEqual([
        { id: '1', email: 'test' },
        { id: '2', email: 'test2' },
      ])
    }, 30000)
  },
)
