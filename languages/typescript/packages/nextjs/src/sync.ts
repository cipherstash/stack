import { type NextRequest, NextResponse } from 'next/server'
import { logger } from '../../utils/logger'
import { setCtsToken } from './cts'
import { forwardCtsSession } from './forward'
import {
  CS_COOKIE_NAME,
  type CtsSession,
  clearCtsSession,
  readCtsSession,
  type SessionOwner,
  sessionBelongsTo,
  writeCtsSession,
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
 *
 * Whenever the cookie is written or cleared, the request forwarded to the rest
 * of this request's handlers is updated to match, so a server component
 * calling `getCtsToken()` never sees the session this call replaced.
 *
 * A session cookie already set on `res` by the caller is not the decision: it
 * is overwritten with the session that was kept, or cleared when none was, so
 * neither the browser nor the forwarded request receives a session nobody
 * checked.
 */
export async function syncCtsSession(
  req: NextRequest,
  identity: SessionIdentity | undefined,
  res?: NextResponse,
): Promise<NextResponse> {
  const callerCookie = res?.cookies.get(CS_COOKIE_NAME)
  const { response, keptSession } = await decideSession(req, identity, res)

  // The decision left the caller's own session cookie in place when the
  // cookie on the response is still the one the caller set.
  const responseCookie = response.cookies.get(CS_COOKIE_NAME)
  const callerCookieSurvived =
    callerCookie !== undefined &&
    responseCookie !== undefined &&
    responseCookie.value === callerCookie.value
  if (callerCookieSurvived) {
    if (keptSession) {
      writeCtsSession(response, keptSession, keptSession.owner)
    } else if (responseCookie.value !== '') {
      clearCtsSession(response)
    }
  }

  return forwardCtsSession(req, response)
}

type SessionDecision = {
  response: NextResponse
  /** The request's own session, when it was checked and kept. */
  keptSession?: CtsSession
}

/**
 * The session decision {@link syncCtsSession} makes, before the forwarded
 * request is brought in line with it: returns `res` (or a pass-through
 * response) with the session cookie kept, written or deleted, and the
 * request's session when it was the one kept.
 */
async function decideSession(
  req: NextRequest,
  identity: SessionIdentity | undefined,
  res: NextResponse | undefined,
): Promise<SessionDecision> {
  const rawSession = req.cookies.get(CS_COOKIE_NAME)?.value
  const passThrough = () => res ?? NextResponse.next()

  if (!identity) {
    if (rawSession) {
      logger.debug(
        'No user is signed in, so the CipherStash session was reset.',
      )
      return { response: clearCtsSession(passThrough()) }
    }

    logger.debug(
      'No user is signed in, so the CipherStash session was not set.',
    )
    return { response: passThrough() }
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
    return { response: passThrough(), keptSession: session }
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
    return {
      response: rawSession ? clearCtsSession(passThrough()) : passThrough(),
    }
  }

  const minted = await setCtsToken(oidcToken, res, {
    clearOnFailure: rawSession !== undefined && rawSession !== '',
  })
  return { response: minted }
}
