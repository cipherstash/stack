/**
 * The cookie/session surface: `getCtsToken`, `resetCtsToken`, `protectMiddleware`.
 *
 * This file predates the jseql -> protect rebrand and had been dead ever since:
 * the package carried no `test` script, so nothing ran it, and it had drifted
 * far enough that it could not even be collected (a `vi.mock` factory closing
 * over a `const` declared below it — `Cannot access 'mockReset' before
 * initialization`). Its assertions had drifted too: `getCtsToken` has returned
 * `{ success, ctsToken }` / `{ success, error }` rather than the bare token or
 * `null` for several majors. Repaired here alongside wiring the script up, so
 * the CTS refusal coverage in `cts-refusal.test.ts` actually runs.
 *
 * `setCtsToken` is mocked through `../src/cts`, which is the module
 * `protectMiddleware` imports it from — mocking the barrel it is re-exported
 * through would not intercept the call.
 */
import { type NextRequest, NextResponse } from 'next/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('next/headers', () => ({
  cookies: vi.fn(),
}))

vi.mock('../../utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  },
}))

vi.mock('../src/cts', () => ({
  fetchCtsToken: vi.fn(),
  setCtsToken: vi.fn(),
}))

import { cookies } from 'next/headers'
import { logger } from '../../utils/logger'
import { fetchCtsToken, setCtsToken } from '../src/cts'
import {
  CS_COOKIE_NAME,
  type CtsToken,
  getCtsToken,
  protectMiddleware,
  resetCtsToken,
} from '../src/index'

/**
 * An unsigned JWT carrying just a `sub`. `decodeJwt` does not verify, so this is
 * enough to exercise the subject comparison in `protectMiddleware`.
 */
const jwtWithSubject = (sub: string) =>
  [
    Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
    Buffer.from(JSON.stringify({ sub })).toString('base64url'),
    '',
  ].join('.')

/** Stub `cookies()` for the server-component path. */
const requestCookie = (value: string | undefined) => {
  vi.mocked(cookies).mockResolvedValue({
    get: () => (value === undefined ? undefined : { value }),
    // biome-ignore lint/suspicious/noExplicitAny: only `get` is exercised here
  } as any)
}

/** A `NextRequest` carrying (or not carrying) a CipherStash session cookie. */
const requestWithSession = (sessionValue?: string) =>
  ({
    cookies: {
      get: vi.fn((name: string) =>
        name === CS_COOKIE_NAME && sessionValue !== undefined
          ? { value: sessionValue }
          : undefined,
      ),
    },
  }) as unknown as NextRequest

beforeEach(() => {
  vi.mocked(setCtsToken).mockImplementation(
    async (_oidcToken: string, res?: NextResponse) =>
      res ?? NextResponse.next(),
  )
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('getCtsToken', () => {
  it('returns the parsed token when the session cookie is present', async () => {
    const ctsToken: CtsToken = { accessToken: 'fake_token', expiry: 999999 }
    requestCookie(JSON.stringify(ctsToken))

    const result = await getCtsToken()

    expect(result).toEqual({ success: true, ctsToken })
    expect(logger.debug).not.toHaveBeenCalledWith(
      'No CipherStash session cookie found in the request.',
    )
  })

  it('reports a failure when there is no cookie and no JWT to exchange', async () => {
    requestCookie(undefined)

    const result = await getCtsToken()

    expect(result).toEqual({
      success: false,
      error: 'No CipherStash session cookie found in the request.',
    })
    expect(logger.debug).toHaveBeenCalledWith(
      'No CipherStash session cookie found in the request.',
    )
  })

  it('exchanges the supplied JWT with CTS when there is no cookie', async () => {
    requestCookie(undefined)
    vi.mocked(fetchCtsToken).mockResolvedValue({
      success: true,
      ctsToken: { accessToken: 'minted', expiry: 1 },
    })

    const result = await getCtsToken('a-user-jwt')

    expect(fetchCtsToken).toHaveBeenCalledWith('a-user-jwt')
    expect(result).toEqual({
      success: true,
      ctsToken: { accessToken: 'minted', expiry: 1 },
    })
  })
})

describe('resetCtsToken', () => {
  it('deletes the session cookie on the provided NextResponse', () => {
    const response = NextResponse.next()
    const mockDelete = vi.spyOn(response.cookies, 'delete')

    const updatedResponse = resetCtsToken(response)

    expect(mockDelete).toHaveBeenCalledWith(CS_COOKIE_NAME)
    expect(updatedResponse).toBe(response)
  })

  it('creates a new NextResponse when none is provided', () => {
    const response = resetCtsToken()

    expect(response).toBeInstanceOf(NextResponse)
    expect(response.cookies.get(CS_COOKIE_NAME)?.value).toBe('')
  })
})

describe('protectMiddleware', () => {
  it('sets a session when a JWT is supplied and there is no session cookie', async () => {
    const req = requestWithSession(undefined)

    await protectMiddleware('a-user-jwt', req)

    expect(setCtsToken).toHaveBeenCalledWith('a-user-jwt', undefined)
  })

  it('leaves the session alone when the JWT and session are the same user', async () => {
    // The CTS access token's `sub` is the OIDC one prefixed with `CS|`.
    const session: CtsToken = {
      accessToken: jwtWithSubject('CS|user-1'),
      expiry: 999999,
    }
    const req = requestWithSession(JSON.stringify(session))
    const res = NextResponse.next()

    const result = await protectMiddleware(jwtWithSubject('user-1'), req, res)

    expect(setCtsToken).not.toHaveBeenCalled()
    expect(result).toBe(res)
  })

  it('re-mints the session when the JWT belongs to a different user', async () => {
    const session: CtsToken = {
      accessToken: jwtWithSubject('CS|user-1'),
      expiry: 999999,
    }
    const req = requestWithSession(JSON.stringify(session))
    const oidcToken = jwtWithSubject('user-2')

    await protectMiddleware(oidcToken, req)

    expect(setCtsToken).toHaveBeenCalledWith(oidcToken, undefined)
  })

  it('resets the session when no JWT is supplied but a session cookie exists', async () => {
    const session: CtsToken = { accessToken: 'whatever', expiry: 999999 }
    const req = requestWithSession(JSON.stringify(session))

    const result = await protectMiddleware('', req)

    expect(logger.debug).toHaveBeenCalledWith(
      'The JWT token was undefined, so the CipherStash session was reset.',
    )
    expect(result.cookies.get(CS_COOKIE_NAME)?.value).toBe('')
    expect(setCtsToken).not.toHaveBeenCalled()
  })

  it('passes the request through when there is neither a JWT nor a session', async () => {
    const req = requestWithSession(undefined)

    const response = await protectMiddleware('', req)

    expect(response).toBeInstanceOf(NextResponse)
    expect(logger.debug).toHaveBeenCalledWith(
      'The JWT token was undefined, so the CipherStash session was not set.',
    )
  })
})
