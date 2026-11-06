import { decodeJwt } from 'jose'
import type { NextResponse } from 'next/server'

/**
 * The CipherStash session cookie: the one module that knows its name, its
 * format and the attributes it is written with.
 *
 * The cookie is client-controlled input. Everything that reads it goes through
 * {@link readCtsSession}, which never throws, so a tampered or truncated value
 * reads as "no session" instead of a 500 on every matched route.
 */
export const CS_COOKIE_NAME = '__cipherstash_cts_session'

export type CtsToken = {
  accessToken: string
  expiry: number
}

/**
 * What the cookie holds: the CTS token, plus the subject of the OIDC token it
 * was minted from.
 *
 * The subject is recorded at mint time rather than read back out of the CTS
 * access token, so ownership never depends on how CTS chooses to shape its own
 * `sub`. It is not a security boundary against the cookie's holder (who
 * already holds the bearer token); it stops a session left in a shared browser
 * by one user being handed to the next.
 */
export type CtsSession = CtsToken & { subject?: string }

/**
 * Parse a raw session cookie value. Returns `undefined` for a missing value,
 * for anything that is not JSON of the `{ accessToken, expiry }` shape, and for
 * a session whose `expiry` has passed.
 */
export function readCtsSession(
  raw: string | undefined,
  now: number = Date.now(),
): CtsSession | undefined {
  if (!raw) return undefined

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return undefined
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return undefined
  }

  const { accessToken, expiry, subject } = parsed as Record<string, unknown>
  if (
    typeof accessToken !== 'string' ||
    accessToken === '' ||
    typeof expiry !== 'number' ||
    !Number.isFinite(expiry) ||
    expiry * 1000 <= now
  ) {
    return undefined
  }

  return typeof subject === 'string' && subject !== ''
    ? { accessToken, expiry, subject }
    : { accessToken, expiry }
}

/**
 * The `sub` of a JWT, exactly as written. The signature is NOT verified: the
 * caller has already authenticated the token, and this only labels the session
 * minted from it. Returns `undefined` for anything that does not decode or
 * carries no non-empty string `sub`.
 */
export function subjectOfJwt(jwt: string): string | undefined {
  let sub: unknown
  try {
    sub = decodeJwt(jwt).sub
  } catch {
    return undefined
  }

  return typeof sub === 'string' && sub !== '' ? sub : undefined
}

/**
 * Whether `session` was minted for `subject`. An unknown subject on either side
 * (including a cookie written before subjects were recorded) is never a match:
 * a session whose owner cannot be established must not be handed to anyone.
 */
export function sessionBelongsTo(
  session: CtsSession,
  subject: string | undefined,
): boolean {
  return session.subject !== undefined && session.subject === subject
}

/** The CTS token alone, without the bookkeeping the cookie carries. */
export function ctsTokenOf({ accessToken, expiry }: CtsSession): CtsToken {
  return { accessToken, expiry }
}

/**
 * Write the session cookie. The value is a bearer token, so it is `httpOnly`
 * (nothing in this package reads it client-side, and page script must not be
 * able to exfiltrate it) and `secure` in production. `secure` is relaxed outside
 * production only so plain-HTTP development servers keep working.
 */
export function writeCtsSession(
  response: NextResponse,
  token: CtsToken,
  subject: string | undefined,
) {
  const session: CtsSession = subject
    ? { ...ctsTokenOf(token), subject }
    : ctsTokenOf(token)

  response.cookies.set({
    name: CS_COOKIE_NAME,
    value: JSON.stringify(session),
    expires: new Date(token.expiry * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  })
  return response
}

/** Delete the session cookie on `response`. */
export function clearCtsSession(response: NextResponse) {
  response.cookies.delete(CS_COOKIE_NAME)
  return response
}
