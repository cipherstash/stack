import type { ClerkMiddlewareAuth } from '@clerk/nextjs/server'
import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import { logger } from '../../../utils/logger'
import { setCtsToken } from '../cts'
import { CS_COOKIE_NAME, resetCtsToken } from '../index'

export const protectClerkMiddleware = async (
  auth: ClerkMiddlewareAuth,
  req: NextRequest,
) => {
  const { userId, getToken } = await auth()
  const ctsSession = req.cookies.has(CS_COOKIE_NAME)

  if (userId && !ctsSession) {
    const oidcToken = await getToken()

    if (!oidcToken) {
      logger.debug(
        'No Clerk token found in the request, so the CipherStash session was not set.',
      )

      return NextResponse.next()
    }

    return await setCtsToken(oidcToken)
  }

  if (!userId && ctsSession) {
    logger.debug(
      'No Clerk token found in the request, so the CipherStash session was reset.',
    )

    return resetCtsToken()
  }

  logger.debug(
    'No Clerk token found in the request, so the CipherStash session was not set.',
  )

  return NextResponse.next()
}
