import { cookies } from 'next/headers'
import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { logger } from '../../utils/logger'
import { fetchCtsToken } from './cts'
import {
  CS_COOKIE_NAME,
  type CtsToken,
  clearCtsSession,
  ctsTokenOf,
  ownerOfJwt,
  readCtsSession,
  sessionBelongsTo,
} from './session'
import { syncCtsSession } from './sync'

export { CS_COOKIE_NAME, type CtsToken }

export type GetCtsTokenResponse = Promise<
  | {
      success: false
      error: string
      /**
       * The refusal code CTS attached, when it refused for a reason the caller
       * can branch on — `USAGE_LIMIT_EXCEEDED` for a billing refusal, for
       * example. Parsed out of the `/api/authorize` error body; `undefined` for
       * every failure that did not carry one, which includes every failure that
       * never reached CTS.
       *
       * NOT validated against a known set: the taxonomy belongs to CipherStash
       * token service and ships on its own release train, so a code newer than
       * this build must still reach you.
       */
      authCode?: string
      ctsToken?: never
    }
  | {
      success: true
      error?: never
      authCode?: never
      ctsToken: CtsToken
    }
>

type GetCtsToken = {
  /**
   * The CipherStash session cookie for the current request, returned as-is.
   *
   * @deprecated Pass the user's OIDC token. With no token there is no identity
   * to check the cookie against, so a session left behind by a sign-out on a
   * route the middleware does not cover is returned to whoever calls this
   * next. Call `resetCtsToken` when a user signs out on such a route.
   */
  (): GetCtsTokenResponse
  /**
   * The CipherStash session for the current request.
   *
   * With `oidcToken`, the session cookie is only returned when it was minted
   * for that token's issuer and subject; otherwise (no cookie, a malformed
   * cookie, or a cookie belonging to someone else) a fresh session is fetched
   * for `oidcToken`. Without it, the cookie is returned as-is, so pass the
   * user's token whenever you have one.
   *
   * `oidcToken` must be a token your application has already authenticated:
   * this function reads its `iss` and `sub` without verifying its signature,
   * to decide which session it may reuse. CTS verifies it when a session is
   * minted.
   */
  (oidcToken: string | undefined): GetCtsTokenResponse
}

export const getCtsToken: GetCtsToken = async (
  oidcToken?: string,
): GetCtsTokenResponse => {
  const cookieStore = await cookies()
  const rawSession = cookieStore.get(CS_COOKIE_NAME)?.value
  const session = readCtsSession(rawSession)

  if (rawSession && !session) {
    logger.debug(
      'The CipherStash session cookie is malformed or expired and was ignored.',
    )
  }

  if (oidcToken) {
    if (session && sessionBelongsTo(session, ownerOfJwt(oidcToken))) {
      return { success: true, ctsToken: ctsTokenOf(session) }
    }

    logger.debug(
      'No CipherStash session for the supplied JWT was found in the request. The JWT will be used to fetch a new CipherStash session.',
    )

    return await fetchCtsToken(oidcToken)
  }

  if (!session) {
    logger.debug('No CipherStash session cookie found in the request.')
    return {
      success: false,
      error: 'No CipherStash session cookie found in the request.',
    }
  }

  return { success: true, ctsToken: ctsTokenOf(session) }
}

/**
 * Delete the CipherStash session cookie, on `res` or on a new pass-through
 * response. Use it when a user signs out on a route the middleware does not
 * cover.
 */
export const resetCtsToken = (res?: NextResponse) =>
  clearCtsSession(res ?? NextResponse.next())

/**
 * Keep the CipherStash session cookie in step with the user `oidcToken`
 * identifies. A session is only reused for the issuer and subject it was
 * minted for; otherwise one is minted from `oidcToken`. An empty `oidcToken`
 * means nobody is signed in, and the cookie is cleared.
 *
 * `oidcToken` must be a token your application has already authenticated. Its
 * `iss` and `sub` are read without verifying its signature: this keeps the
 * session in step with an identity you trust, it does not establish one.
 */
export const protectMiddleware = async (
  oidcToken: string,
  req: NextRequest,
  res?: NextResponse,
) =>
  await syncCtsSession(
    req,
    oidcToken
      ? {
          owner: ownerOfJwt(oidcToken),
          getOidcToken: async () => oidcToken,
        }
      : undefined,
    res,
  )
