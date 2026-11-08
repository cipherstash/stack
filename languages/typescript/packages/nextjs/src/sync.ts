import { NextResponse } from 'next/server'
import { logger } from '../../utils/logger'
import { setCtsToken } from './cts'
import {
  clearCtsSession,
  readCtsSession,
  type SessionOwner,
  sessionBelongsTo,
} from './session'

/**
 * The signed-in user, as a middleware sees them. The caller is responsible for
 * having authenticated this identity: nothing here verifies a token.
 */
export type SessionIdentity = {
  /**
   * The identity the session must have been minted for. `undefined` when it
   * cannot be established, in which case no session is ever reused.
   */
  owner: SessionOwner | undefined
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
 * - Signed in, with an unexpired session minted for this identity (issuer and
 *   subject): pass through.
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

  if (!identity.owner) {
    logger.debug(
      'The signed-in identity has no readable issuer and subject, so no CipherStash session can be reused for it and one will be minted on every request.',
    )
  }

  const session = readCtsSession(rawSession)
  if (session && sessionBelongsTo(session, identity.owner)) {
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
