import type { NextRequest, NextResponse } from 'next/server'
import { CS_COOKIE_NAME } from './session'

/**
 * Next.js's request-header override protocol, as `NextResponse.next({ request:
 * { headers } })` writes it: `x-middleware-override-headers` lists the request
 * headers the forwarded request carries, and `x-middleware-request-<name>`
 * holds each value. Next.js reads both and strips them before the response
 * reaches the browser.
 */
const OVERRIDE_HEADERS = 'x-middleware-override-headers'

/** The names of every header in `headers`, lower-cased as `Headers` stores them. */
function headerNames(headers: Headers): string[] {
  const names: string[] = []
  headers.forEach((_value, key) => {
    names.push(key)
  })
  return names
}
const REQUEST_HEADER_PREFIX = 'x-middleware-request-'

/**
 * Whether `headers` belong to a middleware response that hands the request on
 * to a page or route handler: `NextResponse.next()` marks one with
 * `x-middleware-next`, `NextResponse.rewrite()` with `x-middleware-rewrite`.
 */
function continuesRequest(headers: Headers): boolean {
  return headers.has('x-middleware-next') || headers.has('x-middleware-rewrite')
}

/**
 * Make the request the rest of this request's handlers see agree with the
 * session cookie `response` writes or deletes.
 *
 * Applies only when `response` continues the request (`NextResponse.next()`
 * or a rewrite); any other response is returned unchanged.
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
  // Only a response that lets the request continue (`NextResponse.next()`, or
  // a rewrite) has a downstream handler to update. A redirect or a response
  // the middleware answers itself goes straight back to the browser, so it
  // is left alone rather than given a copy of the request headers.
  if (!continuesRequest(headers)) return response

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
