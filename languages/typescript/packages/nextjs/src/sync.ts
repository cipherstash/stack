import { NextResponse } from 'next/server'
import { logger } from '../../utils/logger'
import { setCtsToken } from './cts'
import { clearCtsSession, readCtsSession, sessionBelongsTo } from './session'

/** The signed-in user, as a middleware sees them. */
export type SessionIdentity = {
  /** The subject the session must have been minted for. */
  subject: string | undefined
  /**
   * The OIDC token to mint a new session with. Called only when the existing
   * session cannot be reused, so a middleware can defer fetching it.
   */
  getOidcToken: () => Promise<string | null | undefined>
}

/**
 * Bring the CipherStash session cookie in line with who is signed in. The one
 * decision both `protectMiddleware` and `protectClerkMiddleware` make:
 *
 * - Signed in, with an unexpired session minted for this subject: pass through.
 * - Signed in otherwise (no session, a malformed or expired one, or one minted
 *   for someone else): mint a session for this user. If there is no token to
 *   mint with, or CTS refuses, a stale cookie is cleared rather than kept.
 * - Signed out, with a session cookie: clear it.
 */
export async function syncCtsSession(
  rawSession: string | undefined,
  identity: SessionIdentity | undefined,
  res?: NextResponse,
): Promise<NextResponse> {
  const response = () => res ?? NextResponse.next()

  if (!identity) {
    if (rawSession) {
      logger.debug(
        'No user is signed in, so the CipherStash session was reset.',
      )
      return clearCtsSession(response())
    }

    logger.debug(
      'No user is signed in, so the CipherStash session was not set.',
    )
    return response()
  }

  const session = readCtsSession(rawSession)
  if (session && sessionBelongsTo(session, identity.subject)) {
    logger.debug(
      'The CipherStash session belongs to the signed-in user and was kept.',
    )
    return response()
  }

  if (rawSession) {
    logger.debug(
      'The CipherStash session is malformed, expired, or belongs to a different user, so it will be replaced.',
    )
  }

  const oidcToken = await identity.getOidcToken()
  if (!oidcToken) {
    logger.debug(
      'No token was available for the signed-in user, so the CipherStash session was not set.',
    )
    return rawSession ? clearCtsSession(response()) : response()
  }

  return await setCtsToken(oidcToken, res, {
    clearOnFailure: rawSession !== undefined && rawSession !== '',
  })
}
