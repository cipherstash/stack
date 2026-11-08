import { decodeJwt } from 'jose'
import type { NextRequest, NextResponse } from 'next/server'
import { logger } from '../../utils/logger'

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

  const value = JSON.stringify(session)
  // Browsers drop a cookie whose name and value exceed 4096 bytes, which would
  // leave this session unset and mint a new one on every request.
  if (CS_COOKIE_NAME.length + encodeURIComponent(value).length > 4096) {
    logger.error(
      'The CipherStash session is larger than browsers accept in one cookie, so it may not be stored and a new session will be fetched on later requests.',
    )
  }

  response.cookies.set({
    name: CS_COOKIE_NAME,
    value,
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

const OVERRIDE_HEADERS = 'x-middleware-override-headers'

function headerNames(headers: Headers): string[] {
  const names: string[] = []
  headers.forEach((_value, key) => {
    names.push(key)
  })
  return names
}
const REQUEST_HEADER_PREFIX = 'x-middleware-request-'

/**
 * Make the request the rest of this request's handlers see agree with the
 * session cookie `response` writes or deletes.
 *
 * A `Set-Cookie` on the middleware response only reaches the browser. Next.js
 * releases before 14.2.10 do not copy it into the request that route handlers
 * and server components read, so without this a user switch would leave the
 * previous user's session visible to `getCtsToken()` for the rest of the
 * request. The forwarded request is changed through the same headers
 * `NextResponse.next({ request: { headers } })` writes. Overriding request
 * headers replaces the whole set, so every other header is carried across, and
 * an override the caller already put on `response` is extended, not replaced.
 *
 * When `response` leaves the session cookie alone, the request's own session
 * is what was decided on. With no override on `response`, Next.js forwards it
 * as-is and nothing is changed. With one, the forwarded cookie is set to the
 * request's session (or to none): an override that carries a session puts
 * back the one this middleware checked, and one that leaves out `cookie`, and
 * so would drop the session, gets it added.
 */
export function forwardCtsSession(req: NextRequest, response: NextResponse) {
  const headers = response.headers
  const existing = headers.get(OVERRIDE_HEADERS)
  const existingKeys = existing
    ? existing
        .split(',')
        .map((key) => key.trim())
        .filter(Boolean)
    : undefined

  const written = response.cookies.get(CS_COOKIE_NAME)
  if (!written && existingKeys === undefined) return response
  const value = written
    ? written.value
    : (req.cookies.get(CS_COOKIE_NAME)?.value ?? '')

  const keys = existingKeys ?? headerNames(req.headers)

  if (!existing) {
    req.headers.forEach((headerValue, key) => {
      headers.set(`${REQUEST_HEADER_PREFIX}${key}`, headerValue)
    })
  }

  const currentCookie = keys.includes('cookie')
    ? (headers.get(`${REQUEST_HEADER_PREFIX}cookie`) ?? '')
    : existing
      ? ''
      : (req.headers.get('cookie') ?? '')

  // Work on the raw header so every other cookie is forwarded byte for byte.
  const pairs = currentCookie
    .split(';')
    .map((pair) => pair.trim())
    .filter((pair) => pair !== '' && pair.split('=', 1)[0] !== CS_COOKIE_NAME)
  if (value !== '') {
    pairs.push(`${CS_COOKIE_NAME}=${encodeURIComponent(value)}`)
  }

  // `cookie` always stays in the override list, set to an empty header when no
  // cookie is left: Next.js ignores an empty override list, and dropping
  // `cookie` from a list that named nothing else would forward the original
  // request cookie, previous session included.
  const otherKeys = keys.filter((key) => key !== 'cookie')
  headers.set(`${REQUEST_HEADER_PREFIX}cookie`, pairs.join('; '))
  headers.set(OVERRIDE_HEADERS, [...otherKeys, 'cookie'].join(','))

  return response
}
