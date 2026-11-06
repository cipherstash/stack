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
  const { userId, getToken } = await auth()

  // The Clerk `userId` is the `sub` of the Clerk session token `getToken()`
  // returns, which is the subject the session is labelled with when minted.
  return await syncCtsSession(
    req.cookies.get(CS_COOKIE_NAME)?.value,
    userId ? { subject: userId, getOidcToken: () => getToken() } : undefined,
  )
}
