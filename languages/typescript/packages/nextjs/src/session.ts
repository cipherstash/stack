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
 * Who a session was minted for: the `iss` and `sub` of the OIDC token it was
 * exchanged from. Both, because a `sub` is only unique within its issuer.
 */
export type SessionOwner = { issuer: string; subject: string }

/**
 * What the cookie holds: the CTS token, plus the {@link SessionOwner} of the
 * OIDC token it was minted from.
 *
 * The owner is recorded at mint time rather than read back out of the CTS
 * access token, so ownership never depends on how CTS shapes its own `sub`.
 *
 * Trust model: the owner is unsigned metadata in a client-held cookie, and
 * nothing here verifies a JWT signature. It is not a security boundary against
 * the cookie's holder, who already holds the bearer token. It stops a session
 * left in a shared browser by one user being handed to the next, which is only
 * meaningful if the identity it is compared with was authenticated by the
 * caller (Clerk's middleware, or your own verification of the OIDC token).
 */
export type CtsSession = CtsToken & { owner?: SessionOwner }

const nonEmptyString = (value: unknown): value is string =>
  typeof value === 'string' && value !== ''

/**
 * Validate a value as a {@link CtsToken}: an object with a non-empty string
 * `accessToken` and a finite numeric `expiry`. Used for both the cookie and the
 * CTS `/api/authorize` success body, so neither boundary trusts a cast.
 */
export function parseCtsToken(value: unknown): CtsToken | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined
  }

  const { accessToken, expiry } = value as Record<string, unknown>
  if (
    !nonEmptyString(accessToken) ||
    typeof expiry !== 'number' ||
    !Number.isFinite(expiry)
  ) {
    return undefined
  }

  return { accessToken, expiry }
}

function parseOwner(value: unknown): SessionOwner | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const { issuer, subject } = value as Record<string, unknown>
  return nonEmptyString(issuer) && nonEmptyString(subject)
    ? { issuer, subject }
    : undefined
}

/**
 * Parse a raw session cookie value. Returns `undefined` for a missing value,
 * for anything that is not JSON of the `{ accessToken, expiry }` shape, and for
 * a session whose `expiry` has passed. A missing or malformed `owner` leaves the
 * session unowned, which never matches anyone.
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

  const token = parseCtsToken(parsed)
  if (!token || token.expiry * 1000 <= now) return undefined

  const owner = parseOwner((parsed as Record<string, unknown>).owner)
  return owner ? { ...token, owner } : token
}

/**
 * The `iss` and `sub` of a JWT, exactly as written. The signature is NOT
 * verified: the caller must already have authenticated the token, and this only
 * labels the session minted from it. Returns `undefined` for anything that does
 * not decode, or lacks a non-empty string `iss` or `sub`.
 */
export function ownerOfJwt(jwt: string): SessionOwner | undefined {
  let claims: { iss?: unknown; sub?: unknown }
  try {
    claims = decodeJwt(jwt)
  } catch {
    return undefined
  }

  return nonEmptyString(claims.iss) && nonEmptyString(claims.sub)
    ? { issuer: claims.iss, subject: claims.sub }
    : undefined
}

/**
 * Whether `session` was minted for `owner`. An unknown owner on either side
 * (including a cookie written before owners were recorded) is never a match: a
 * session whose owner cannot be established must not be handed to anyone.
 */
export function sessionBelongsTo(
  session: CtsSession,
  owner: SessionOwner | undefined,
): boolean {
  return (
    session.owner !== undefined &&
    owner !== undefined &&
    session.owner.issuer === owner.issuer &&
    session.owner.subject === owner.subject
  )
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
  owner: SessionOwner | undefined,
) {
  const session: CtsSession = owner
    ? { ...ctsTokenOf(token), owner }
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
