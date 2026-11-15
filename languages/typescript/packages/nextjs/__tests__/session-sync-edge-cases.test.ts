/**
 * Edge cases of the session decision `syncCtsSession` makes: a Clerk session
 * with no `iss`, a Clerk `getToken` that rejects, and a caller's session cookie
 * that happens to equal the session this request minted.
 *
 * `fetch` is stubbed, so minting runs for real against a fake CTS.
 */
import type { ClerkMiddlewareAuth } from '@clerk/nextjs/server'
import { NextRequest, NextResponse } from 'next/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('next/headers', () => ({ cookies: vi.fn() }))

vi.mock('../../utils/logger', () => ({
  logger: { debug: vi.fn(), error: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import { protectClerkMiddleware } from '../src/clerk'
import { setCtsToken } from '../src/cts'
import { CS_COOKIE_NAME, protectMiddleware } from '../src/index'

const ISSUER = 'https://idp.example'
const EXPIRY = 1_900_000_000

const jwtFor = (sub: string, iss: string = ISSUER) =>
  [
    Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
    Buffer.from(JSON.stringify({ iss, sub })).toString('base64url'),
    '',
  ].join('.')

const sessionValue = (sub: string) =>
  JSON.stringify({
    accessToken: jwtFor(`CS|${sub}`),
    expiry: EXPIRY,
    owner: { issuer: ISSUER, subject: sub },
  })

/** A fake CTS that answers every request with the same token. */
const ctsMintsTheSameToken = () =>
  vi.fn(
    async () =>
      new Response(
        JSON.stringify({ accessToken: jwtFor('CS|user_A'), expiry: EXPIRY }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
  )

const request = (cookie?: string) => {
  const req = new NextRequest('https://app.example/dashboard')
  if (cookie !== undefined) req.cookies.set(CS_COOKIE_NAME, cookie)
  return req
}

const clerkAuth = (
  userId: string,
  claims: Record<string, unknown>,
  getToken: () => Promise<string | null>,
) =>
  (async () => ({
    userId,
    sessionClaims: { sub: userId, ...claims },
    getToken,
  })) as unknown as ClerkMiddlewareAuth

/** The middleware's outcome, with a rejection returned rather than thrown. */
const outcomeOf = (result: Promise<NextResponse>) =>
  result.catch((error: unknown) => error)

beforeEach(() => {
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  vi.stubGlobal('fetch', ctsMintsTheSameToken())
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  vi.clearAllMocks()
})

describe('protectClerkMiddleware when the Clerk session has no issuer', () => {
  const noIssuer = () => clerkAuth('user_A', {}, async () => jwtFor('user_A'))

  it('mints on every request instead of reusing a session', async () => {
    const cookie = sessionValue('user_A')

    await protectClerkMiddleware(noIssuer(), request(cookie))
    await protectClerkMiddleware(noIssuer(), request(cookie))

    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('clears the cookie when the mint fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('unavailable', { status: 500 })),
    )

    const res = await protectClerkMiddleware(
      noIssuer(),
      request(sessionValue('user_A')),
    )

    expect(res.cookies.get(CS_COOKIE_NAME)?.value).toBe('')
  })
})

describe('protectClerkMiddleware when Clerk cannot produce a token', () => {
  const getTokenRejects = async () => {
    throw new Error('Clerk could not issue a token')
  }

  it('clears a stale session instead of failing the request', async () => {
    const outcome = await outcomeOf(
      protectClerkMiddleware(
        clerkAuth('user_A', { iss: ISSUER }, getTokenRejects),
        request(sessionValue('user_B')),
      ),
    )

    expect(outcome).toBeInstanceOf(NextResponse)
    expect((outcome as NextResponse).cookies.get(CS_COOKIE_NAME)?.value).toBe(
      '',
    )
    expect(fetch).not.toHaveBeenCalled()
  })

  it('passes the request through when there is no session to clear', async () => {
    const outcome = await outcomeOf(
      protectClerkMiddleware(
        clerkAuth('user_A', { iss: ISSUER }, getTokenRejects),
        request(),
      ),
    )

    expect(outcome).toBeInstanceOf(NextResponse)
    expect(
      (outcome as NextResponse).cookies.get(CS_COOKIE_NAME),
    ).toBeUndefined()
  })
})

describe('a session cookie set by the caller', () => {
  it('does not clear a freshly minted session that equals it', async () => {
    const oidcToken = jwtFor('user_A')
    const minted = (await setCtsToken(oidcToken)).cookies.get(CS_COOKIE_NAME)
      ?.value as string
    vi.mocked(fetch).mockClear()

    const callerRes = NextResponse.next()
    callerRes.cookies.set(CS_COOKIE_NAME, minted)

    const res = await protectMiddleware(oidcToken, request(), callerRes)

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(res.cookies.get(CS_COOKIE_NAME)?.value).toBe(minted)
  })
})
