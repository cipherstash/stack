import { type Result, withResult } from '@byteslice/result'
import { loadWorkSpaceId } from '../../../utils/config'
import { logger } from '../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '..'

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
        'You have not defined a workspace ID in your config file, or the CS_WORKSPACE_ID environment variable.',
      )
    }

    if (ctsToken) {
      this.ctsToken = ctsToken
    }

    this.workspaceId = workspaceId
    this.context = context
    logger.debug('Successfully initialized the EQL lock context.')
  }

  async identify(jwtToken: string): Promise<Result<LockContext, ProtectError>> {
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
        type: ProtectErrorTypes.CtsTokenError,
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
        type: ProtectErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )

    return identifiedLockContext
  }

  getLockContext(): Promise<Result<GetLockContextResponse, ProtectError>> {
    return withResult(
      () => {
        if (!this.ctsToken?.accessToken && !this.ctsToken?.expiry) {
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
        type: ProtectErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )
  }
}
