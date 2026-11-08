import type { ClerkMiddlewareAuth } from '@clerk/nextjs/server'
import type { NextRequest } from 'next/server'
import { CS_COOKIE_NAME } from '../session'
import { syncCtsSession } from '../sync'

/**
 * Keep the CipherStash session cookie in step with the signed-in Clerk user.
 *
 * A session is only reused for the Clerk user it was minted for. One left
 * behind by another user (a multi-session `setActive` switch, or a sign-out on
 * a route the matcher does not cover) is replaced, or cleared if a new one
 * cannot be minted. When nobody is signed in, the cookie is cleared.
 */
export const protectClerkMiddleware = async (
  auth: ClerkMiddlewareAuth,
  req: NextRequest,
) => {
  const { userId, sessionClaims, getToken } = await auth()
  const issuer = sessionClaims?.iss

  // `userId` and `sessionClaims` come from the Clerk session token Clerk has
  // already verified, and are the `sub` and `iss` of the token `getToken()`
  // returns, which is what a session is labelled with when minted.
  return await syncCtsSession(
    req.cookies.get(CS_COOKIE_NAME)?.value,
    userId
      ? {
          owner:
            typeof issuer === 'string' && issuer !== ''
              ? { issuer, subject: userId }
              : undefined,
          getOidcToken: () => getToken(),
        }
      : undefined,
  )
}
