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
 * Requires `USER_JWT` plus `CS_WORKSPACE_CRN` / `CS_CLIENT_ID` /
 * `CS_CLIENT_KEY`; skips silently if `USER_JWT` is absent.
 */
const users = encryptedTable('users', {
  email: encryptedColumn('email').freeTextSearch().equality().orderAndRange(),
  address: encryptedColumn('address').freeTextSearch(),
})

const IDENTITY_CLAIM = { identityClaim: ['sub'] }

/** Split `crn:<region>:<workspace-id>` into its region and workspace id. */
function regionAndWorkspaceFromCrn(crn: string): {
  region: string
  workspaceId: string
} {
  const match = crn.match(/^crn:([^:]+):(.+)$/)
  if (!match) {
    throw new Error(
      `CS_WORKSPACE_CRN must look like "crn:<region>:<workspace-id>", got "${crn}"`,
    )
  }
  return { region: match[1], workspaceId: match[2] }
}

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
  const { region, workspaceId } = regionAndWorkspaceFromCrn(crn)

  return Encryption({
    schemas: [users],
    config: {
      strategy: OidcFederationStrategy.create(region, workspaceId, () =>
        Promise.resolve(userJwt),
      ),
    },
  })
}

describe('identity-bound encryption via OidcFederationStrategy + lock context', () => {
  it('should encrypt and decrypt a payload bound to the user identity', async () => {
    const userJwt = process.env.USER_JWT
    if (!userJwt) {
      console.log('Skipping lock context test - no USER_JWT provided')
      return
    }

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
    const userJwt = process.env.USER_JWT
    if (!userJwt) {
      console.log('Skipping lock context test - no USER_JWT provided')
      return
    }

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
    const userJwt = process.env.USER_JWT
    if (!userJwt) {
      console.log('Skipping lock context test - no USER_JWT provided')
      return
    }

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
    const userJwt = process.env.USER_JWT
    if (!userJwt) {
      console.log('Skipping lock context test - no USER_JWT provided')
      return
    }

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
})
