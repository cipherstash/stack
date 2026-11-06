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
  readCtsSession,
  sessionBelongsTo,
  subjectOfJwt,
} from './session'
import { syncCtsSession } from './sync'

export { CS_COOKIE_NAME, type CtsToken }

export type GetCtsTokenResponse = Promise<
  | {
      success: boolean
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
      success: boolean
      error?: never
      authCode?: never
      ctsToken: CtsToken
    }
>

/**
 * The CipherStash session for the current request.
 *
 * With `oidcToken`, the session cookie is only returned when it was minted for
 * that token's subject; otherwise (no cookie, a malformed cookie, or a cookie
 * belonging to someone else) a fresh session is fetched for `oidcToken`. Without
 * it, the cookie is returned as-is, so pass the user's token whenever you have
 * one.
 */
export const getCtsToken = async (oidcToken?: string): GetCtsTokenResponse => {
  const cookieStore = await cookies()
  const rawSession = cookieStore.get(CS_COOKIE_NAME)?.value
  const session = readCtsSession(rawSession)

  if (rawSession && !session) {
    logger.debug(
      'The CipherStash session cookie is malformed or expired and was ignored.',
    )
  }

  if (oidcToken) {
    if (session && sessionBelongsTo(session, subjectOfJwt(oidcToken))) {
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

export const resetCtsToken = (res?: NextResponse) =>
  clearCtsSession(res ?? NextResponse.next())

/**
 * Keep the CipherStash session cookie in step with the user `oidcToken`
 * identifies. A session is only reused for the subject it was minted for;
 * otherwise one is minted from `oidcToken`. An empty `oidcToken` means nobody
 * is signed in, and the cookie is cleared.
 */
export const protectMiddleware = async (
  oidcToken: string,
  req: NextRequest,
  res?: NextResponse,
) =>
  await syncCtsSession(
    req.cookies.get(CS_COOKIE_NAME)?.value,
    oidcToken
      ? {
          subject: subjectOfJwt(oidcToken),
          getOidcToken: async () => oidcToken,
        }
      : undefined,
    res,
  )
