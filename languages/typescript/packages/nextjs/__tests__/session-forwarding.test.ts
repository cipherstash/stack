/**
 * A rewrite continues the request just as `NextResponse.next()` does, so the
 * route it lands on must see the session the middleware decided on, not the
 * one the request arrived with.
 *
 * `fetch` is stubbed, so the session is minted for real against a fake CTS. The
 * forwarded request is read the way Next.js reads it: the headers named by
 * `x-middleware-override-headers`, each from its `x-middleware-request-<name>`.
 */
import { NextRequest, NextResponse } from 'next/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('next/headers', () => ({ cookies: vi.fn() }))

vi.mock('../../utils/logger', () => ({
  logger: { debug: vi.fn(), error: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import { CS_COOKIE_NAME, protectMiddleware } from '../src/index'

const ISSUER = 'https://idp.example'
const REWRITE_TARGET = 'https://app.example/rewritten'

const inAnHour = () => Math.floor(Date.now() / 1000) + 3600

const encodeSegment = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString('base64url')

const jwtFor = (sub: string) =>
  [
    encodeSegment({ alg: 'none' }),
    encodeSegment({ iss: ISSUER, sub }),
    '',
  ].join('.')

const accessTokenFor = (sub: string) => `token-for-${sub}`

const sessionCookieFor = (sub: string) =>
  JSON.stringify({
    accessToken: accessTokenFor(sub),
    expiry: inAnHour(),
    owner: { issuer: ISSUER, subject: sub },
  })

/** A fake CTS that mints a token naming whichever OIDC subject it is handed. */
const ctsMintsForCaller = () =>
  vi.fn(async (_url: string, init: RequestInit) => {
    const { oidcToken } = JSON.parse(String(init.body)) as { oidcToken: string }
    const { sub } = JSON.parse(
      Buffer.from(oidcToken.split('.')[1], 'base64url').toString(),
    ) as { sub: string }
    return new Response(
      JSON.stringify({ accessToken: accessTokenFor(sub), expiry: inAnHour() }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    )
  })

/** A request signed in as `user_A`, with another cookie and header to carry. */
const requestFromUserA = () => {
  const req = new NextRequest('https://app.example/dashboard', {
    headers: { 'x-trace': 'abc' },
  })
  req.cookies.set(CS_COOKIE_NAME, sessionCookieFor('user_A'))
  req.cookies.set('theme', 'dark')
  return req
}

/**
 * The headers of the request the rewritten route receives. With no override
 * Next.js forwards `original` as it arrived; with one, only the listed headers
 * survive, each taken from its `x-middleware-request-<name>` header.
 */
const forwardedHeaders = (res: Response, original: NextRequest) => {
  const override = res.headers.get('x-middleware-override-headers')
  if (override === null) return new Headers(original.headers)

  const forwarded = new Headers()
  for (const name of override.split(',').map((key) => key.trim())) {
    const value = res.headers.get(`x-middleware-request-${name}`)
    if (value) forwarded.set(name, value)
  }
  return forwarded
}

/** One cookie's decoded value from a `cookie` request header. */
const cookieIn = (headers: Headers, name: string) => {
  for (const pair of (headers.get('cookie') ?? '').split(';')) {
    const trimmed = pair.trim()
    const at = trimmed.indexOf('=')
    if (at > 0 && trimmed.slice(0, at) === name) {
      return decodeURIComponent(trimmed.slice(at + 1))
    }
  }
  return undefined
}

/** The access token in the forwarded session cookie, if there is one. */
const forwardedAccessToken = (headers: Headers) => {
  const session = cookieIn(headers, CS_COOKIE_NAME)
  return session === undefined
    ? undefined
    : (JSON.parse(session) as { accessToken: string }).accessToken
}

beforeEach(() => {
  vi.stubEnv('CS_WORKSPACE_CRN', 'crn:ap-southeast-2.aws:test-workspace')
  vi.stubGlobal('fetch', ctsMintsForCaller())
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  vi.clearAllMocks()
})

describe('forwarding the session through a rewrite', () => {
  it('gives the rewritten route the new session after a user switch', async () => {
    const req = requestFromUserA()

    const res = await protectMiddleware(
      jwtFor('user_B'),
      req,
      NextResponse.rewrite(REWRITE_TARGET),
    )

    expect(res.headers.get('x-middleware-rewrite')).toBe(REWRITE_TARGET)
    const forwarded = forwardedHeaders(res, req)
    expect(forwardedAccessToken(forwarded)).toBe(accessTokenFor('user_B'))
    expect(cookieIn(forwarded, 'theme')).toBe('dark')
    expect(forwarded.get('x-trace')).toBe('abc')
  })

  it('gives the rewritten route no session after a sign-out', async () => {
    const req = requestFromUserA()

    const res = await protectMiddleware(
      '',
      req,
      NextResponse.rewrite(REWRITE_TARGET),
    )

    expect(res.headers.get('x-middleware-rewrite')).toBe(REWRITE_TARGET)
    const forwarded = forwardedHeaders(res, req)
    expect(forwardedAccessToken(forwarded)).toBeUndefined()
    expect(cookieIn(forwarded, 'theme')).toBe('dark')
    expect(forwarded.get('x-trace')).toBe('abc')
  })

  it('leaves a rewrite without request overrides when the session is kept', async () => {
    const req = requestFromUserA()

    const res = await protectMiddleware(
      jwtFor('user_A'),
      req,
      NextResponse.rewrite(REWRITE_TARGET),
    )

    expect(res.headers.get('x-middleware-override-headers')).toBeNull()
    expect(forwardedAccessToken(forwardedHeaders(res, req))).toBe(
      accessTokenFor('user_A'),
    )
  })
})
