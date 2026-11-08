/**
 * CIP-5154: the CipherStash session cookie is client-controlled input carrying a
 * bearer token. These cover the three defects that issue grouped:
 *
 * 1. the cookie must be written `httpOnly` (and `secure` in production);
 * 2. a session minted for one user must never be handed to another — in the
 *    Clerk middleware and in `getCtsToken(oidcToken)`;
 * 3. a malformed cookie must read as "no session", not throw.
 *
 * `fetch` is stubbed, so `setCtsToken` / `fetchCtsToken` run for real against a
 * fake CTS: the assertions are on the `Set-Cookie` the middleware emits.
 */
import type { ClerkMiddlewareAuth } from '@clerk/nextjs/server'
import { NextRequest, NextResponse } from 'next/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('next/headers', () => ({ cookies: vi.fn() }))

vi.mock('../../utils/logger', () => ({
  logger: { debug: vi.fn(), error: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import { cookies } from 'next/headers'
import { logger } from '../../utils/logger'
import { protectClerkMiddleware } from '../src/clerk'
import { setCtsToken } from '../src/cts'
import {
  CS_COOKIE_NAME,
  type CtsToken,
  getCtsToken,
  protectMiddleware,
} from '../src/index'
import {
  type CtsSession,
  ctsTokenOf,
  ownerOfJwt,
  readCtsSession,
  sessionBelongsTo,
} from '../src/session'

/** The issuer every test identity comes from unless a test says otherwise. */
const ISSUER = 'https://idp.example'

const jwtWithSubject = (sub: unknown) =>
  [
    Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
    Buffer.from(JSON.stringify({ iss: ISSUER, sub })).toString('base64url'),
    '',
  ].join('.')

/** A cookie session as `setCtsToken` writes it for an OIDC subject. */
const sessionFor = (sub: string): CtsSession => ({
  accessToken: jwtWithSubject(`CS|${sub}`),
  expiry: 1_900_000_000,
  owner: { issuer: ISSUER, subject: sub },
})

/** Whether the fake CTS minted `token` for the OIDC subject `sub`. */
const mintedFor = (token: CtsToken | undefined, sub: string) =>
  token !== undefined && ownerOfJwt(token.accessToken)?.subject === `CS|${sub}`

/** A fake CTS that mints a token for whichever OIDC subject it is handed. */
const ctsMintsForCaller = () =>
  vi.fn(async (_url: string, init: RequestInit) => {
    const { oidcToken } = JSON.parse(String(init.body))
    const owner = ownerOfJwt(oidcToken)
    const sub = owner?.subject ?? 'unknown'
    // The minted token names the caller's issuer too, so a session kept across
    // an issuer switch is told apart from the one that replaces it.
    const accessToken = [
      Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
      Buffer.from(
        JSON.stringify({ iss: owner?.issuer ?? ISSUER, sub: `CS|${sub}` }),
      ).toString('base64url'),
      '',
    ].join('.')
    return new Response(
      JSON.stringify({ ...ctsTokenOf(sessionFor(sub)), accessToken }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    )
  })

const ctsRefuses = () =>
  vi.fn(async () => new Response('Authorization failed', { status: 401 }))

const request = (cookie?: string) => {
  const req = new NextRequest('https://app.example/dashboard')
  if (cookie !== undefined) req.cookies.set(CS_COOKIE_NAME, cookie)
  return req
}

/** The `Set-Cookie` line the response carries for the session cookie, if any. */
const sessionSetCookie = (res: Response) =>
  res.headers
    .getSetCookie()
    .find((line) => line.startsWith(`${CS_COOKIE_NAME}=`))

/** The session the response writes, or `null` when it deletes the cookie. */
const writtenSession = (res: NextResponse) => {
  const cookie = res.cookies.get(CS_COOKIE_NAME)
  if (!cookie) return undefined
  return cookie.value === '' ? null : (JSON.parse(cookie.value) as CtsToken)
}

const clerkAuth = (
  userId: string | null,
  token: string | null,
  claims: Record<string, unknown> = { iss: ISSUER },
) =>
  (async () => ({
    userId,
    sessionClaims: userId ? { sub: userId, ...claims } : null,
    getToken: vi.fn(async () => token),
  })) as unknown as ClerkMiddlewareAuth

const serverCookie = (value: string | undefined) => {
  vi.mocked(cookies).mockResolvedValue({
    get: () => (value === undefined ? undefined : { value }),
    // biome-ignore lint/suspicious/noExplicitAny: only `get` is exercised here
  } as any)
}

beforeEach(() => {
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  vi.stubGlobal('fetch', ctsMintsForCaller())
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  vi.clearAllMocks()
})

describe('the session cookie attributes', () => {
  it('is written httpOnly, SameSite=Lax, on path /', async () => {
    const res = await setCtsToken(jwtWithSubject('user-1'))
    const line = sessionSetCookie(res)

    expect(line).toBeDefined()
    expect(line).toMatch(/;\s*HttpOnly/i)
    expect(line).toMatch(/;\s*SameSite=Lax/i)
    expect(line).toMatch(/;\s*Path=\//i)
  })

  it('is Secure in production', async () => {
    vi.stubEnv('NODE_ENV', 'production')
    const res = await setCtsToken(jwtWithSubject('user-1'))

    expect(sessionSetCookie(res)).toMatch(/;\s*Secure/i)
  })

  it('is not Secure outside production, so http://localhost works', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    const res = await setCtsToken(jwtWithSubject('user-1'))

    expect(sessionSetCookie(res)).not.toMatch(/;\s*Secure/i)
  })
})

describe('protectClerkMiddleware: a session is only reused for its own user', () => {
  it('passes a session minted for the signed-in user through untouched', async () => {
    const getToken = vi.fn(async () => jwtWithSubject('user_A'))
    const auth = (async () => ({
      userId: 'user_A',
      sessionClaims: { iss: ISSUER, sub: 'user_A' },
      getToken,
    })) as unknown as ClerkMiddlewareAuth

    const res = await protectClerkMiddleware(
      auth,
      request(JSON.stringify(sessionFor('user_A'))),
    )

    expect(writtenSession(res)).toBeUndefined()
    expect(getToken).not.toHaveBeenCalled()
    expect(fetch).not.toHaveBeenCalled()
  })

  it("replaces another user's session with one for the signed-in user", async () => {
    const res = await protectClerkMiddleware(
      clerkAuth('user_B', jwtWithSubject('user_B')),
      request(JSON.stringify(sessionFor('user_A'))),
    )

    const written = writtenSession(res)
    expect(written).toBeTruthy()
    expect(
      sessionBelongsTo(written as CtsSession, {
        issuer: ISSUER,
        subject: 'user_B',
      }),
    ).toBe(true)
    // The label and the bearer token itself must both be user B's.
    expect(mintedFor(written ?? undefined, 'user_B')).toBe(true)
  })

  it("clears another user's session when the replacement cannot be minted", async () => {
    vi.stubGlobal('fetch', ctsRefuses())

    const res = await protectClerkMiddleware(
      clerkAuth('user_B', jwtWithSubject('user_B')),
      request(JSON.stringify(sessionFor('user_A'))),
    )

    expect(writtenSession(res)).toBeNull()
  })

  it("clears another user's session when Clerk has no token to mint with", async () => {
    const res = await protectClerkMiddleware(
      clerkAuth('user_B', null),
      request(JSON.stringify(sessionFor('user_A'))),
    )

    expect(writtenSession(res)).toBeNull()
  })

  it('mints a session when the user has none', async () => {
    const res = await protectClerkMiddleware(
      clerkAuth('user_A', jwtWithSubject('user_A')),
      request(),
    )

    expect(
      sessionBelongsTo(writtenSession(res) as CtsSession, {
        issuer: ISSUER,
        subject: 'user_A',
      }),
    ).toBe(true)
  })

  it('clears the session when nobody is signed in', async () => {
    const res = await protectClerkMiddleware(
      clerkAuth(null, null),
      request(JSON.stringify(sessionFor('user_A'))),
    )

    expect(writtenSession(res)).toBeNull()
  })

  it('replaces a malformed session instead of throwing', async () => {
    const res = await protectClerkMiddleware(
      clerkAuth('user_A', jwtWithSubject('user_A')),
      request('not-json'),
    )

    expect(
      sessionBelongsTo(writtenSession(res) as CtsSession, {
        issuer: ISSUER,
        subject: 'user_A',
      }),
    ).toBe(true)
  })
})

describe('getCtsToken(oidcToken): the cookie is only returned for its own user', () => {
  it('returns the cookie session when it belongs to the token subject', async () => {
    const session = sessionFor('user-1')
    serverCookie(JSON.stringify(session))

    const result = await getCtsToken(jwtWithSubject('user-1'))

    expect(result).toEqual({ success: true, ctsToken: ctsTokenOf(session) })
    expect(fetch).not.toHaveBeenCalled()
  })

  it("fetches a fresh session instead of returning another user's cookie", async () => {
    serverCookie(JSON.stringify(sessionFor('user-1')))

    const result = await getCtsToken(jwtWithSubject('user-2'))

    expect(result.success).toBe(true)
    expect(mintedFor(result.ctsToken, 'user-2')).toBe(true)
  })

  it("does not fall back to another user's cookie when CTS refuses", async () => {
    vi.stubGlobal('fetch', ctsRefuses())
    serverCookie(JSON.stringify(sessionFor('user-1')))

    const result = await getCtsToken(jwtWithSubject('user-2'))

    expect(result.success).toBe(false)
    expect(result.ctsToken).toBeUndefined()
  })
})

describe('a malformed session cookie reads as no session', () => {
  const malformed = [
    'not-json',
    '{"accessToken":',
    'null',
    '[]',
    '"a string"',
    '{"accessToken":42,"expiry":1}',
    '{"accessToken":"x"}',
    '{"accessToken":"","expiry":1}',
  ]

  it.each(malformed)('getCtsToken() reports no session for %j', async (raw) => {
    serverCookie(raw)

    await expect(getCtsToken()).resolves.toEqual({
      success: false,
      error: 'No CipherStash session cookie found in the request.',
    })
  })

  it.each(malformed)(
    'getCtsToken(jwt) fetches a session for %j',
    async (raw) => {
      serverCookie(raw)

      const result = await getCtsToken(jwtWithSubject('user-1'))

      expect(mintedFor(result.ctsToken, 'user-1')).toBe(true)
    },
  )

  it.each(malformed)('protectMiddleware(jwt) re-mints for %j', async (raw) => {
    const res = await protectMiddleware(jwtWithSubject('user-1'), request(raw))

    expect(
      sessionBelongsTo(writtenSession(res) as CtsSession, {
        issuer: ISSUER,
        subject: 'user-1',
      }),
    ).toBe(true)
  })

  it.each(malformed)('protectMiddleware() clears %j', async (raw) => {
    const res = await protectMiddleware('', request(raw))

    expect(writtenSession(res)).toBeNull()
  })

  it('protectMiddleware(jwt) re-mints an expired session', async () => {
    const res = await protectMiddleware(
      jwtWithSubject('user-1'),
      request(
        JSON.stringify({
          accessToken: 'opaque',
          expiry: 1,
          owner: { issuer: ISSUER, subject: 'user-1' },
        }),
      ),
    )

    expect(
      sessionBelongsTo(writtenSession(res) as CtsSession, {
        issuer: ISSUER,
        subject: 'user-1',
      }),
    ).toBe(true)
  })

  it('protectMiddleware(jwt) reuses an unexpired session with an opaque access token', async () => {
    // Ownership is the recorded owner, so the CTS token's own format is
    // irrelevant to reuse.
    const res = await protectMiddleware(
      jwtWithSubject('user-1'),
      request(
        JSON.stringify({
          accessToken: 'opaque',
          expiry: Math.floor(Date.now() / 1000) + 3600,
          owner: { issuer: ISSUER, subject: 'user-1' },
        }),
      ),
    )

    expect(writtenSession(res)).toBeUndefined()
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('session helpers', () => {
  it('reads a well-formed session', () => {
    const session = sessionFor('user-1')
    expect(readCtsSession(JSON.stringify(session))).toEqual(session)
  })

  it('reads the subject exactly as written, CS| prefix included', () => {
    expect(ownerOfJwt(jwtWithSubject('CS|user-1'))).toEqual({
      issuer: ISSUER,
      subject: 'CS|user-1',
    })
    expect(ownerOfJwt(jwtWithSubject('user-1'))?.subject).toBe('user-1')
  })

  it('reads an expired session as no session', () => {
    const session = sessionFor('user-1')
    const raw = JSON.stringify(session)
    expect(readCtsSession(raw, session.expiry * 1000)).toBeUndefined()
    expect(readCtsSession(raw, session.expiry * 1000 - 1)).toEqual(session)
  })

  it('reads a session written before subjects were recorded as unowned', () => {
    const legacy = ctsTokenOf(sessionFor('user-1'))
    const session = readCtsSession(JSON.stringify(legacy)) as CtsSession
    expect(session).toEqual(legacy)
    expect(
      sessionBelongsTo(session, { issuer: ISSUER, subject: 'user-1' }),
    ).toBe(false)
  })

  it('reports no owner for a non-JWT, a missing sub, or a non-string sub', () => {
    expect(ownerOfJwt('opaque')).toBeUndefined()
    expect(ownerOfJwt(jwtWithSubject(undefined))).toBeUndefined()
    expect(ownerOfJwt(jwtWithSubject(42))).toBeUndefined()
    expect(ownerOfJwt(jwtWithSubject(''))).toBeUndefined()
  })

  it('reports no owner for a token without an issuer', () => {
    const noIssuer = [
      Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
      Buffer.from(JSON.stringify({ sub: 'user-1' })).toString('base64url'),
      '',
    ].join('.')
    expect(ownerOfJwt(noIssuer)).toBeUndefined()
  })

  it('never matches when either subject is unknown', () => {
    const subjectless = ctsTokenOf(sessionFor('user-1'))
    expect(sessionBelongsTo(subjectless, undefined)).toBe(false)
    expect(sessionBelongsTo(sessionFor('user-1'), undefined)).toBe(false)
    expect(
      sessionBelongsTo(subjectless, { issuer: ISSUER, subject: 'user-1' }),
    ).toBe(false)
  })
})

describe('review follow-ups', () => {
  /** A CTS whose access-token `sub` is its own principal id, not the IdP one. */
  const ctsMintsOpaquePrincipal = () =>
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            accessToken: jwtWithSubject('CS|3f1c2a9e-principal'),
            expiry: 1_900_000_000,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    )

  it('reuses a Clerk session without depending on the CTS subject format', async () => {
    vi.stubGlobal('fetch', ctsMintsOpaquePrincipal())
    const first = await protectClerkMiddleware(
      clerkAuth('user_A', jwtWithSubject('user_A')),
      request(),
    )
    const cookie = first.cookies.get(CS_COOKIE_NAME)?.value as string
    vi.mocked(fetch).mockClear()

    const second = await protectClerkMiddleware(
      clerkAuth('user_A', jwtWithSubject('user_A')),
      request(cookie),
    )

    expect(fetch).not.toHaveBeenCalled()
    expect(writtenSession(second)).toBeUndefined()
  })

  it('does not treat a CS|-prefixed IdP subject as the unprefixed user', async () => {
    // Minted for IdP subject `alice`; a different user whose IdP subject is
    // literally `CS|alice` must not be handed it.
    const minted = await setCtsToken(jwtWithSubject('alice'))
    const cookie = minted.cookies.get(CS_COOKIE_NAME)?.value as string
    vi.mocked(fetch).mockClear()

    const res = await protectMiddleware(
      jwtWithSubject('CS|alice'),
      request(cookie),
    )

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(writtenSession(res)).toBeTruthy()
  })

  it('re-mints an expired session instead of passing it through', async () => {
    const expired = {
      ...sessionFor('user_A'),
      expiry: Math.floor(Date.now() / 1000) - 60,
    }

    const res = await protectClerkMiddleware(
      clerkAuth('user_A', jwtWithSubject('user_A')),
      request(JSON.stringify(expired)),
    )

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(writtenSession(res)).toBeTruthy()
  })

  it('emits no cookie deletion when a mint fails and there was no cookie', async () => {
    vi.stubGlobal('fetch', ctsRefuses())

    const res = await protectClerkMiddleware(
      clerkAuth('user_A', jwtWithSubject('user_A')),
      request(),
    )

    expect(sessionSetCookie(res)).toBeUndefined()
  })
})

describe('issuer-aware ownership', () => {
  const jwtFrom = (iss: string | undefined, sub: string) =>
    [
      Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
      Buffer.from(JSON.stringify({ iss, sub })).toString('base64url'),
      '',
    ].join('.')

  /** The issuer of the bearer token the response writes, and of its owner. */
  const issuerOfWritten = (res: NextResponse) => {
    const raw = res.cookies.get(CS_COOKIE_NAME)?.value
    const session = readCtsSession(raw)
    return {
      token: session && ownerOfJwt(session.accessToken)?.issuer,
      owner: session?.owner?.issuer,
    }
  }

  it('does not reuse a session for the same sub from a different issuer', async () => {
    const minted = await setCtsToken(jwtFrom('https://idp-a.example', 'alice'))
    const cookie = minted.cookies.get(CS_COOKIE_NAME)?.value as string
    vi.mocked(fetch).mockClear()

    const res = await protectMiddleware(
      jwtFrom('https://idp-b.example', 'alice'),
      request(cookie),
    )

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(issuerOfWritten(res)).toEqual({
      token: 'https://idp-b.example',
      owner: 'https://idp-b.example',
    })
  })

  it('reuses a session for the same issuer and sub', async () => {
    const minted = await setCtsToken(jwtFrom('https://idp-a.example', 'alice'))
    const cookie = minted.cookies.get(CS_COOKIE_NAME)?.value as string
    vi.mocked(fetch).mockClear()

    const res = await protectMiddleware(
      jwtFrom('https://idp-a.example', 'alice'),
      request(cookie),
    )

    expect(fetch).not.toHaveBeenCalled()
    expect(writtenSession(res)).toBeUndefined()
  })

  it('does not reuse a Clerk session minted by a different issuer', async () => {
    const minted = await setCtsToken(jwtFrom('https://other.example', 'user_A'))
    const cookie = minted.cookies.get(CS_COOKIE_NAME)?.value as string
    vi.mocked(fetch).mockClear()

    const res = await protectClerkMiddleware(
      clerkAuth('user_A', jwtFrom('https://clerk.app.example', 'user_A'), {
        iss: 'https://clerk.app.example',
      }),
      request(cookie),
    )

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(issuerOfWritten(res)).toEqual({
      token: 'https://clerk.app.example',
      owner: 'https://clerk.app.example',
    })
  })
})

describe('the request seen by downstream handlers', () => {
  /** The cookies Next forwards to route handlers for this request, if overridden. */
  const forwardedCookies = (res: Response) => {
    const override = res.headers.get('x-middleware-override-headers')
    if (override === null) return undefined
    // A request header left out of the override list is deleted.
    if (
      !override
        .split(',')
        .map((key) => key.trim())
        .includes('cookie')
    ) {
      return {} as Record<string, string>
    }
    const header = res.headers.get('x-middleware-request-cookie') ?? ''
    return Object.fromEntries(
      header
        .split(';')
        .map((pair) => pair.trim())
        .filter(Boolean)
        .map((pair) => {
          const at = pair.indexOf('=')
          return [pair.slice(0, at), decodeURIComponent(pair.slice(at + 1))]
        }),
    ) as Record<string, string>
  }

  const requestWith = (cookies: Record<string, string>) => {
    const req = new NextRequest('https://app.example/dashboard', {
      headers: { 'x-trace': 'abc' },
    })
    for (const [name, value] of Object.entries(cookies)) {
      req.cookies.set(name, value)
    }
    return req
  }

  it("forwards the new session, not the previous user's, after a switch", async () => {
    const previous = JSON.stringify(sessionFor('user_A'))

    const res = await protectClerkMiddleware(
      clerkAuth('user_B', jwtWithSubject('user_B')),
      requestWith({ [CS_COOKIE_NAME]: previous, theme: 'dark' }),
    )

    const forwarded = forwardedCookies(res)
    expect(forwarded).toBeDefined()
    expect(forwarded?.[CS_COOKIE_NAME]).not.toBe(previous)
    expect(
      sessionBelongsTo(
        readCtsSession(forwarded?.[CS_COOKIE_NAME]) as CtsSession,
        { issuer: ISSUER, subject: 'user_B' },
      ),
    ).toBe(true)
    expect(forwarded?.theme).toBe('dark')
    // Overriding request headers replaces the whole set, so the rest must be
    // carried across untouched.
    expect(res.headers.get('x-middleware-request-x-trace')).toBe('abc')
  })

  it('forwards no session after a sign-out', async () => {
    const res = await protectClerkMiddleware(
      clerkAuth(null, null),
      requestWith({
        [CS_COOKIE_NAME]: JSON.stringify(sessionFor('user_A')),
        theme: 'dark',
      }),
    )

    const forwarded = forwardedCookies(res)
    expect(forwarded).toBeDefined()
    expect(forwarded?.[CS_COOKIE_NAME]).toBeUndefined()
    expect(forwarded?.theme).toBe('dark')
  })

  it("forwards no session when another user's cannot be replaced", async () => {
    vi.stubGlobal('fetch', ctsRefuses())

    const res = await protectClerkMiddleware(
      clerkAuth('user_B', jwtWithSubject('user_B')),
      requestWith({ [CS_COOKIE_NAME]: JSON.stringify(sessionFor('user_A')) }),
    )

    expect(forwardedCookies(res)?.[CS_COOKIE_NAME]).toBeUndefined()
    expect(forwardedCookies(res)).toBeDefined()
  })

  it('leaves the request alone when the session is kept', async () => {
    const res = await protectClerkMiddleware(
      clerkAuth('user_A', jwtWithSubject('user_A')),
      requestWith({ [CS_COOKIE_NAME]: JSON.stringify(sessionFor('user_A')) }),
    )

    expect(res.headers.get('x-middleware-override-headers')).toBeNull()
  })

  it("keeps a caller's own request header overrides when forwarding", async () => {
    const headers = new Headers({ 'x-tenant': 't1' })
    const callerRes = NextResponse.next({ request: { headers } })

    const res = await protectMiddleware(
      jwtWithSubject('user-2'),
      requestWith({ [CS_COOKIE_NAME]: JSON.stringify(sessionFor('user-1')) }),
      callerRes,
    )

    const keys = (res.headers.get('x-middleware-override-headers') ?? '').split(
      ',',
    )
    expect(keys).toContain('x-tenant')
    expect(keys).toContain('cookie')
    expect(res.headers.get('x-middleware-request-x-tenant')).toBe('t1')
    expect(
      sessionBelongsTo(
        readCtsSession(forwardedCookies(res)?.[CS_COOKIE_NAME]) as CtsSession,
        { issuer: ISSUER, subject: 'user-2' },
      ),
    ).toBe(true)
  })

  it("does not forward another user's session from a caller's cookie override", async () => {
    // The caller's response already overrides the forwarded cookie with a
    // session for someone else. The middleware keeps the request's own session,
    // so that is the one downstream handlers must see.
    const own = JSON.stringify(sessionFor('user_A'))
    const other = JSON.stringify(sessionFor('user_B'))
    const callerRes = NextResponse.next({
      request: {
        headers: new Headers({
          cookie: `${CS_COOKIE_NAME}=${encodeURIComponent(other)}; theme=dark`,
        }),
      },
    })

    const res = await protectMiddleware(
      jwtWithSubject('user_A'),
      requestWith({ [CS_COOKIE_NAME]: own }),
      callerRes,
    )

    expect(writtenSession(res)).toBeUndefined()
    expect(forwardedCookies(res)?.[CS_COOKIE_NAME]).toBe(own)
    expect(forwardedCookies(res)?.theme).toBe('dark')
  })

  it("forwards no session from a caller's cookie override when signed out", async () => {
    const callerRes = NextResponse.next({
      request: {
        headers: new Headers({
          cookie: `${CS_COOKIE_NAME}=${encodeURIComponent(JSON.stringify(sessionFor('user_B')))}`,
        }),
      },
    })

    const res = await protectMiddleware('', requestWith({}), callerRes)

    expect(forwardedCookies(res)).toBeDefined()
    expect(forwardedCookies(res)?.[CS_COOKIE_NAME]).toBeUndefined()
  })

  it("forwards the kept session through a caller's override that leaves out the cookie", async () => {
    // An override list replaces the forwarded request headers, so one that
    // does not name `cookie` would drop the session the middleware accepted.
    const own = JSON.stringify(sessionFor('user_A'))
    const callerRes = NextResponse.next({
      request: { headers: new Headers({ 'x-tenant': 't1' }) },
    })

    const res = await protectMiddleware(
      jwtWithSubject('user_A'),
      requestWith({ [CS_COOKIE_NAME]: own }),
      callerRes,
    )

    expect(writtenSession(res)).toBeUndefined()
    expect(forwardedCookies(res)?.[CS_COOKIE_NAME]).toBe(own)
    expect(res.headers.get('x-middleware-request-x-tenant')).toBe('t1')
  })
})

describe('clearing through an override that only names the cookie', () => {
  it('keeps the override list non-empty so the old session is not forwarded', async () => {
    // Next.js ignores an empty `x-middleware-override-headers`, which would let
    // the original request cookie (the previous session) through untouched.
    const session = JSON.stringify(sessionFor('user_A'))
    const req = request(session)
    const callerRes = NextResponse.next({
      request: {
        headers: new Headers({
          cookie: `${CS_COOKIE_NAME}=${encodeURIComponent(session)}`,
        }),
      },
    })

    const res = await protectMiddleware('', req, callerRes)

    expect(res.headers.get('x-middleware-override-headers')).toBe('cookie')
    expect(res.headers.get('x-middleware-request-cookie')).toBe('')
  })
})

describe('a CTS transport failure', () => {
  it("clears another user's session instead of throwing", async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('fetch failed')
      }),
    )

    const res = await protectClerkMiddleware(
      clerkAuth('user_B', jwtWithSubject('user_B')),
      request(JSON.stringify(sessionFor('user_A'))),
    )

    expect(writtenSession(res)).toBeNull()
  })

  it('is reported by getCtsToken as a failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('fetch failed')
      }),
    )
    serverCookie(undefined)

    const result = await getCtsToken(jwtWithSubject('user-1'))

    expect(result.success).toBe(false)
  })

  it('keeps the exception text out of the error and the log', async () => {
    const oidcToken = jwtWithSubject('user-1')
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: string, init: RequestInit) => {
        // A fetch wrapper may echo the request body, OIDC token included.
        throw new Error(`request failed: ${String(init.body)}`)
      }),
    )
    serverCookie(undefined)

    const result = await getCtsToken(oidcToken)

    expect(result.success).toBe(false)
    expect(result.error).not.toContain(oidcToken)
    const logged = vi.mocked(logger.error).mock.calls
    expect(logged).toHaveLength(1)
    expect(
      logged.flat().map((arg) => (arg instanceof Error ? arg.message : arg)),
    ).not.toContainEqual(expect.stringContaining('request failed'))
  })
})

describe('an expired token from CTS', () => {
  const ctsMintsExpired = () =>
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({ accessToken: 'expired-token', expiry: 1 }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    )

  it('is reported by getCtsToken as a failure', async () => {
    vi.stubGlobal('fetch', ctsMintsExpired())
    serverCookie(undefined)

    const result = await getCtsToken(jwtWithSubject('user-1'))

    expect(result.success).toBe(false)
  })

  it('is not written, and the stale session is cleared', async () => {
    vi.stubGlobal('fetch', ctsMintsExpired())

    const res = await protectMiddleware(
      jwtWithSubject('user-2'),
      request(JSON.stringify(sessionFor('user-1'))),
    )

    expect(writtenSession(res)).toBeNull()
  })
})
