import { type Result, withResult } from '@byteslice/result'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import { loadWorkSpaceId } from '@/utils/config'
import { logger } from '@/utils/logger'

export type CtsRegions = 'ap-southeast-2'

export type IdentifyOptions = {
  fetchFromCts?: boolean
}

export type CtsToken = {
  accessToken: string
  expiry: number
}

export type Context = {
  identityClaim: string[]
}

export type LockContextOptions = {
  context?: Context
  ctsToken?: CtsToken
}

export type GetLockContextResponse = {
  ctsToken: CtsToken
  context: Context
}

/**
 * Manages CipherStash lock contexts for row-level access control.
 *
 * A `LockContext` ties encryption/decryption operations to an authenticated
 * user identity via CTS (CipherStash Token Service). Call {@link identify}
 * with a user's JWT to obtain a CTS token, then pass the `LockContext`
 * to `.withLockContext()` on any encrypt/decrypt operation.
 *
 * @example
 * ```typescript
 * import { LockContext } from "@cipherstash/stack/identity"
 *
 * const lc = new LockContext()
 * const identified = await lc.identify(userJwt)
 *
 * if (identified.failure) throw new Error(identified.failure.message)
 *
 * const result = await client
 *   .encrypt(value, { column: users.email, table: users })
 *   .withLockContext(identified.data)
 * ```
 */
export class LockContext {
  private ctsToken: CtsToken | undefined
  private workspaceId: string
  private context: Context

  constructor({
    context = { identityClaim: ['sub'] },
    ctsToken,
  }: LockContextOptions = {}) {
    const workspaceId = loadWorkSpaceId()

    if (!workspaceId) {
      throw new Error(
        'You have not defined a workspace ID in your config file, or the CS_WORKSPACE_CRN environment variable.',
      )
    }

    if (ctsToken) {
      this.ctsToken = ctsToken
    }

    this.workspaceId = workspaceId
    this.context = context
    logger.debug('Successfully initialized the EQL lock context.')
  }

  /**
   * Exchange a user's JWT for a CTS token and bind it to this lock context.
   *
   * @param jwtToken - A valid OIDC / JWT token for the current user.
   * @returns A `Result` containing this `LockContext` (now authenticated) or an error.
   *
   * @example
   * ```typescript
   * const lc = new LockContext()
   * const result = await lc.identify(userJwt)
   * if (result.failure) {
   *   console.error("Auth failed:", result.failure.message)
   * }
   * ```
   */
  async identify(
    jwtToken: string,
  ): Promise<Result<LockContext, EncryptionError>> {
    const workspaceId = this.workspaceId

    const ctsEndpoint =
      process.env.CS_CTS_ENDPOINT ||
      'https://ap-southeast-2.aws.auth.viturhosted.net'

    const ctsFetchResult = await withResult(
      () =>
        fetch(`${ctsEndpoint}/api/authorize`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            workspaceId,
            oidcToken: jwtToken,
          }),
        }),
      (error) => ({
        type: EncryptionErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )

    if (ctsFetchResult.failure) {
      return ctsFetchResult
    }

    const identifiedLockContext = await withResult(
      async () => {
        const ctsToken = (await ctsFetchResult.data.json()) as CtsToken

        if (!ctsToken.accessToken) {
          throw new Error(
            'The response from the CipherStash API did not contain an access token. Please contact support.',
          )
        }

        this.ctsToken = ctsToken
        return this
      },
      (error) => ({
        type: EncryptionErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )

    return identifiedLockContext
  }

  /**
   * Retrieve the current CTS token and context for use with encryption operations.
   *
   * Must be called after {@link identify}. Returns the token/context pair that
   * `.withLockContext()` expects.
   *
   * @returns A `Result` containing the CTS token and identity context, or an error
   *   if {@link identify} has not been called.
   */
  getLockContext(): Promise<Result<GetLockContextResponse, EncryptionError>> {
    return withResult(
      () => {
        if (!this.ctsToken?.accessToken || !this.ctsToken?.expiry) {
          throw new Error(
            'The CTS token is not set. Please call identify() with a users JWT token, or pass an existing CTS token to the LockContext constructor before calling getLockContext().',
          )
        }

        return {
          context: this.context,
          ctsToken: this.ctsToken,
        }
      },
      (error) => ({
        type: EncryptionErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )
  }
}
