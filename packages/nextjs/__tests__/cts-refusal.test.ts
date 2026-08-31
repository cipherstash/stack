/**
 * `getCtsToken()` (and the `fetchCtsToken` under it) against a CTS that says no.
 *
 * This package talks to `POST /api/authorize` directly — the same endpoint
 * `LockContext.identify()` in `@cipherstash/stack` calls, and the same one that
 * answers a billing refusal with a `402`. `fetch` RESOLVES for a `402`: nothing
 * throws, so the failure has to be read off the status and the body.
 *
 * Credential-free: `fetch` is stubbed, so there is no CTS round-trip.
 *
 * The bodies below are the ones CTS actually sends, and the two shapes are not
 * the same shape:
 *
 * - A **402** is JSON — `AuthorizeErrorBody` in `cts-web/src/authorize/mod.rs`,
 *   i.e. `{"error":"usage_limit_exceeded","error_description":"...",
 *   "cs_code":"USAGE_LIMIT_EXCEEDED"}`.
 * - **Everything else** is plain text. A live probe answers `401` with the bare
 *   string `Authorization failed: InvalidToken`, and over HTTP/2 with an EMPTY
 *   `statusText` — which is the whole reason this file exists.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// No CipherStash session cookie in the request: that is the branch of
// `getCtsToken` which exchanges the supplied OIDC token with CTS.
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({ get: () => undefined })),
}))

vi.mock('../../utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  },
}))

import { logger } from '../../utils/logger'
import { getCtsToken } from '../src/index'

/**
 * A CTS response as `fetch` would resolve it. `Response` leaves `statusText`
 * empty unless one is passed, which is exactly what the live endpoint does over
 * HTTP/2 — so the pre-fix message really did carry nothing.
 */
const ctsResponds = (
  status: number,
  body: string,
  contentType = 'text/plain; charset=utf-8',
) =>
  vi.fn(
    async () =>
      new Response(body, {
        status,
        headers: { 'content-type': contentType },
      }),
  )

/** A CTS success: the `{ accessToken, expiry }` shape `/api/authorize` mints. */
const ctsIssuesToken = () =>
  vi.fn(
    async () =>
      new Response(
        JSON.stringify({ accessToken: 'cts-token', expiry: 1_900_000_000 }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
  )

/** Every string this failure was logged with, in call order. */
const loggedMessages = () =>
  [...vi.mocked(logger.debug).mock.calls, ...vi.mocked(logger.error).mock.calls]
    .flat()
    .filter((arg): arg is string => typeof arg === 'string')

beforeEach(() => {
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  vi.clearAllMocks()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/** The 402 body CTS sends, as `AuthorizeErrorBody` serialises it. */
const refusalBody = (
  error: string,
  csCode: string | undefined,
  description: string,
) =>
  JSON.stringify({
    error,
    error_description: description,
    // `cs_code` is `skip_serializing_if = "Option::is_none"` upstream, so an
    // absent one is an absent KEY, not a null.
    ...(csCode ? { cs_code: csCode } : {}),
  })

describe('getCtsToken(): a CTS refusal reaches the caller as one', () => {
  it('surfaces a usage-limit 402 with its refusal code and what CTS said', async () => {
    // Pre-fix this returned the bare string "Failed to fetch CTS token: " —
    // `statusText` is empty over HTTP/2, so the caller got a failure with no
    // status, no body, and no code to branch on.
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        refusalBody(
          'usage_limit_exceeded',
          'USAGE_LIMIT_EXCEEDED',
          'Workspace has exceeded its usage limit and cannot issue an access token',
        ),
        'application/json',
      ),
    )

    const result = await getCtsToken('a-user-jwt')

    expect(result.success).toBe(false)
    expect(result.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(result.error).toContain('402')
    // The service's own sentence, not the JSON envelope around it.
    expect(result.error).toContain('Workspace has exceeded its usage limit')
    expect(result.error).not.toContain('error_description')
  })

  it('distinguishes an unprovisioned org from an over-limit one', async () => {
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        refusalBody(
          'org_not_provisioned',
          'ORG_NOT_PROVISIONED',
          'Organisation is not provisioned in the usage system and cannot issue an access token',
        ),
        'application/json',
      ),
    )

    const result = await getCtsToken('a-user-jwt')

    expect(result.authCode).toBe('ORG_NOT_PROVISIONED')
    expect(result.error).toContain('Organisation is not provisioned')
  })

  it('declines an unknown refusal code', async () => {
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        refusalBody('access_denied', 'SOME_FUTURE_REFUSAL', 'Nope.'),
        'application/json',
      ),
    )

    const result = await getCtsToken('a-user-jwt')

    expect(result.authCode).toBeUndefined()
    expect(result.error).toContain('Nope.')
  })

  it('reads a pre-cs_code 402 off `error` when the key is absent', async () => {
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        refusalBody('usage_limit_exceeded', undefined, 'Over the limit.'),
        'application/json',
      ),
    )

    const result = await getCtsToken('a-user-jwt')

    expect(result.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('classifies a legacy OAuth 402 without cs_code as the usage limit', async () => {
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        refusalBody('access_denied', undefined, 'Over the limit.'),
        'application/json',
      ),
    )

    const result = await getCtsToken('a-user-jwt')

    expect(result.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('reads a bodyless 402 as the usage limit', async () => {
    vi.stubGlobal('fetch', ctsResponds(402, ''))

    const result = await getCtsToken('a-user-jwt')

    expect(result.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('degrades to a plain error when the 402 did not come from CTS', async () => {
    // A gateway, WAF or proxy in front of CTS answers with prose or a page of
    // HTML, not an `AuthorizeErrorBody`. That must produce an honest error,
    // never an invented code — reporting it as a billing refusal sends the
    // caller to a billing page for something a retry would have cleared.
    vi.stubGlobal('fetch', ctsResponds(402, 'Payment Required'))

    const result = await getCtsToken('a-user-jwt')

    expect(result.success).toBe(false)
    expect(result.authCode).toBeUndefined()
    expect(result.error).toContain('402')
    expect(result.error).toContain('Payment Required')
  })

  it('logs the reason instead of an empty statusText', async () => {
    // The defect was in the logs as much as in the return value: both lines
    // reported `statusText`, or nothing at all.
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        refusalBody(
          'usage_limit_exceeded',
          'USAGE_LIMIT_EXCEEDED',
          'Workspace has exceeded its usage limit and cannot issue an access token',
        ),
        'application/json',
      ),
    )

    await getCtsToken('a-user-jwt')

    const logged = loggedMessages()
    expect(logged.some((message) => message.includes('402'))).toBe(true)
    expect(
      logged.some((message) =>
        message.includes('Workspace has exceeded its usage limit'),
      ),
    ).toBe(true)
    // Nothing may be logged as a message that trails off into an empty
    // `statusText`.
    expect(logged.every((message) => !/[:\s]$/.test(message))).toBe(true)
  })
})

describe('getCtsToken(): other non-2xx statuses are not mislabelled', () => {
  // Verbatim from a live probe of the real endpoint — an expired or malformed
  // user JWT is by far the likeliest way to land here, and it must not read as
  // a billing problem.
  const cases: ReadonlyArray<[number, string]> = [
    [401, 'Authorization failed: InvalidToken'],
    [403, 'Forbidden'],
    [500, 'Internal Server Error'],
  ]

  for (const [status, body] of cases) {
    it(`keeps a ${status} as a plain CTS token failure`, async () => {
      vi.stubGlobal('fetch', ctsResponds(status, body))

      const result = await getCtsToken('a-user-jwt')

      expect(result.success).toBe(false)
      expect(result.authCode).toBeUndefined()
      // The status and what the server actually said — the two things a caller
      // needs, and neither of which survived before.
      expect(result.error).toContain(String(status))
      expect(result.error).toContain(body)
      // No billing language on a failure that is not a billing failure.
      expect(result.error).not.toMatch(/billing|upgrade|dashboard/i)
    })
  }

  it('survives an empty error body without trailing punctuation debris', async () => {
    vi.stubGlobal('fetch', ctsResponds(502, ''))

    const result = await getCtsToken('a-user-jwt')

    expect(result.success).toBe(false)
    expect(result.error).toContain('502')
    expect(result.error).not.toMatch(/[:\s]$/)
  })

  it('caps a runaway body and does not read a code out of it', async () => {
    // A gateway in front of CTS answers with a page of HTML, not a sentence.
    // The quote is capped so it does not become the whole error, and nothing
    // in it is mistaken for a refusal code.
    const padding = '<html><body>'.padEnd(600, 'x')

    vi.stubGlobal('fetch', ctsResponds(402, padding))

    const result = await getCtsToken('a-user-jwt')

    expect(result.authCode).toBeUndefined()
    expect(result.error).not.toContain(padding)
    expect(result.error?.length).toBeLessThan(padding.length)
  })
})

describe('getCtsToken(): the 2xx paths are unchanged', () => {
  it('still returns the token on the happy path', async () => {
    vi.stubGlobal('fetch', ctsIssuesToken())

    const result = await getCtsToken('a-user-jwt')

    expect(result.success).toBe(true)
    expect(result.error).toBeUndefined()
    expect(result.ctsToken).toEqual({
      accessToken: 'cts-token',
      expiry: 1_900_000_000,
    })
  })

  it('still rejects on a 2xx whose body is not JSON', async () => {
    // Pinned as-is, NOT fixed here: a 200 with an unparseable body throws out of
    // `fetchCtsToken` today, and the refusal fix deliberately leaves the 2xx
    // path alone. Recorded so a later change to it is a decision rather than an
    // accident.
    vi.stubGlobal('fetch', ctsResponds(200, 'not json at all'))

    await expect(getCtsToken('a-user-jwt')).rejects.toThrow()
  })
})
