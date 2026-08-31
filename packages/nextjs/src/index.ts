import { decodeJwt } from 'jose'
import { cookies } from 'next/headers'
import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { logger } from '../../utils/logger'
import { fetchCtsToken, setCtsToken } from './cts'

function getSubjectFromToken(jwt: string): string | undefined {
  const payload = decodeJwt(jwt)

  // The CTS JWT payload has a sub field that starts with "CS|"
  if (typeof payload?.sub === 'string' && payload?.sub.startsWith('CS|')) {
    return payload.sub.slice(3)
  }

  return payload?.sub
}

export const CS_COOKIE_NAME = '__cipherstash_cts_session'

export type CtsToken = {
  accessToken: string
  expiry: number
}

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

export const getCtsToken = async (oidcToken?: string): GetCtsTokenResponse => {
  const cookieStore = await cookies()
  const cookieData = cookieStore.get(CS_COOKIE_NAME)?.value

  if (oidcToken && !cookieData) {
    logger.debug(
      'The CipherStash session cookie was not found in the request, but a JWT token was provided. The JWT token will be used to fetch a new CipherStash session.',
    )

    return await fetchCtsToken(oidcToken)
  }

  if (!cookieData) {
    logger.debug('No CipherStash session cookie found in the request.')
    return {
      success: false,
      error: 'No CipherStash session cookie found in the request.',
    }
  }

  const cts_token = JSON.parse(cookieData) as CtsToken
  return {
    success: true,
    ctsToken: cts_token,
  }
}

export const resetCtsToken = (res?: NextResponse) => {
  if (res) {
    res.cookies.delete(CS_COOKIE_NAME)
    return res
  }

  const response = NextResponse.next()
  response.cookies.delete(CS_COOKIE_NAME)
  return response
}

export const protectMiddleware = async (
  oidcToken: string,
  req: NextRequest,
  res?: NextResponse,
) => {
  const ctsSession = req.cookies.get(CS_COOKIE_NAME)?.value

  if (oidcToken && ctsSession) {
    const ctsToken = JSON.parse(ctsSession) as CtsToken
    const ctsTokenSubject = getSubjectFromToken(ctsToken.accessToken)
    const oidcTokenSubject = getSubjectFromToken(oidcToken)

    if (ctsTokenSubject === oidcTokenSubject) {
      logger.debug(
        'The JWT token and the CipherStash session are both valid for the same user.',
      )

      return res ?? NextResponse.next()
    }

    return await setCtsToken(oidcToken, res)
  }

  if (oidcToken && !ctsSession) {
    logger.debug(
      'The JWT token was defined, so the CipherStash session will be set.',
    )

    return await setCtsToken(oidcToken, res)
  }

  if (!oidcToken && ctsSession) {
    logger.debug(
      'The JWT token was undefined, so the CipherStash session was reset.',
    )

    return resetCtsToken(res)
  }

  logger.debug(
    'The JWT token was undefined, so the CipherStash session was not set.',
  )

  if (res) {
    return res
  }

  return NextResponse.next()
}
