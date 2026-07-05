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
  ctsToken?: CtsToken
  context: Context
}

/**
 * The accepted argument to `.withLockContext()` — either a {@link LockContext}
 * or a plain identity-claim spec (e.g. `{ identityClaim: ['sub'] }`).
 */
export type LockContextInput = LockContext | Context

/**
 * Resolve a {@link LockContextInput} to the {@link Context} (identity claim)
 * that protect-ffi expects. Synchronous — no token round-trip.
 */
export function resolveLockContext(input: LockContextInput): Context {
  // Use a structural check as well as `instanceof` so a `LockContext`
  // constructed in another realm (or from a duplicate module instance) is still
  // resolved rather than slipping through as a raw `Context`.
  return input instanceof LockContext || 'identityContext' in input
    ? (input as LockContext).identityContext
    : input
}

/**
 * Binds an encryption/decryption operation to a user's identity by selecting
 * which JWT claim(s) ZeroKMS bakes into the data key's tag (the *lock context*).
 *
 * The claim **value** is resolved by ZeroKMS from the token that authenticates
 * the request — so to bind to a real end user, authenticate the client as that
 * user with an `OidcFederationStrategy` (from `@cipherstash/auth`) and pass the
 * claim to `.withLockContext()`. The same context must be supplied to decrypt.
 *
 * You can pass a plain `{ identityClaim }` directly — constructing a
 * `LockContext` is optional.
 *
 * @example
 * ```typescript
 * import { Encryption } from "@cipherstash/stack"
 * import { OidcFederationStrategy } from "@cipherstash/auth"
 *
 * // Authenticate the client as the end user (replaces the old identify() flow).
 * const client = await Encryption({
 *   schemas,
 *   config: {
 *     strategy: OidcFederationStrategy.create(workspaceCrn, () => getJwt()),
 *   },
 * })
 *
 * // Bind the key to the user's `sub` claim — no token, no identify().
 * const result = await client
 *   .encrypt(value, { column: users.email, table: users })
 *   .withLockContext({ identityClaim: ["sub"] })
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
   * The identity-claim context this lock context binds to, e.g.
   * `{ identityClaim: ['sub'] }`. Resolved synchronously — `.withLockContext()`
   * uses this directly; no CTS token is required.
   */
  get identityContext(): Context {
    return this.context
  }

  /**
   * Exchange a user's JWT for a CTS token and bind it to this lock context.
   *
   * @deprecated Per-operation CTS tokens were removed in protect-ffi 0.25.
   * Authenticate the client as the user with an `OidcFederationStrategy`
   * (`config.strategy`) instead, and pass the claim to `.withLockContext()`.
   * The token fetched here is no longer used by encryption operations. This
   * method is kept for backwards compatibility and will be removed in a
   * future major release.
   *
   * @param jwtToken - A valid OIDC / JWT token for the current user.
   * @returns A `Result` containing this `LockContext` or an error.
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
   * Retrieve the identity context (and CTS token, if one was set).
   *
   * @deprecated Encryption operations no longer consume a CTS token — they read
   * the identity claim directly via {@link identityContext}. Pass the claim to
   * `.withLockContext()` and authenticate the client with an
   * `OidcFederationStrategy` instead. Kept for backwards compatibility; the
   * returned `ctsToken` is `undefined` unless one was supplied to the
   * constructor or {@link identify} was called.
   */
  getLockContext(): Promise<Result<GetLockContextResponse, EncryptionError>> {
    return withResult(
      () => ({
        context: this.context,
        // Only include `ctsToken` when one was actually set, so the
        // returned shape matches the optional `ctsToken?` type rather
        // than carrying an explicit `undefined`.
        ...(this.ctsToken ? { ctsToken: this.ctsToken } : {}),
      }),
      (error) => ({
        type: EncryptionErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )
  }
}
