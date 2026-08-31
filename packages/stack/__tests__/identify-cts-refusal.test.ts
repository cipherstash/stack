/**
 * `LockContext.identify()` against a CTS that says no.
 *
 * This is the one path in the SDK that talks to CTS directly — `POST
 * /api/authorize`, the very endpoint that answers a billing refusal with a
 * `402` — so it is the one path where the refusal arrives as an HTTP response
 * rather than as a thrown protect-ffi error with `authCode` already on it.
 * `fetch` RESOLVES for a 402: nothing throws, so a `withResult` wrapper alone
 * sees success and the failure has to be read off the status.
 *
 * Credential-free: `fetch` is stubbed, so there is no CTS round-trip.
 *
 * The error bodies below are the ones CTS actually sends, and the two shapes
 * are not the same shape:
 *
 * - A **402** is JSON — `AuthorizeErrorBody` in `cts-web/src/authorize/mod.rs`,
 *   i.e. `{"error":"usage_limit_exceeded","error_description":"...",
 *   "cs_code":"USAGE_LIMIT_EXCEEDED"}`. `cs_code` carries the taxonomy code;
 *   `error` is the lowercase OAuth-ish one.
 * - **Everything else** is `(StatusCode, self.to_string())` — plain text. A
 *   live probe of `POST /api/authorize` answers `401` with `Authorization
 *   failed: InvalidToken` and `422` with a serde deserialisation message, and
 *   those are carried verbatim below.
 *
 * That asymmetry is the whole reason the reader takes `.text()` once and parses
 * defensively rather than calling `.json()`: on the plain-text majority
 * `.json()` throws a `SyntaxError` that displaces the real failure.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EncryptionErrorTypes } from '@/errors'
import { LockContext } from '@/identity'

/** Build a CTS response with a body and status, as `fetch` would resolve it. */
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

beforeEach(() => {
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
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

describe('identify(): a CTS refusal reaches the caller as one', () => {
  it('surfaces a usage-limit 402 with its code and message', async () => {
    // Pre-fix this returned "The response from the CipherStash API did not
    // contain an access token. Please contact support." — a support ticket for
    // a billing state, with no code to branch on and no dashboard to visit.
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

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.type).toBe(EncryptionErrorTypes.CtsTokenError)
    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    // The service's own sentence, not the JSON envelope around it.
    expect(result.failure?.message).toContain(
      'Workspace has exceeded its usage limit',
    )
    expect(result.failure?.message).not.toContain('error_description')
    expect(result.failure?.message).not.toContain('contact support')
  })

  it('distinguishes an unprovisioned org from a usage limit', async () => {
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

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.authCode).toBe('ORG_NOT_PROVISIONED')
    expect(result.failure?.message).toContain('not provisioned')
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

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.authCode).toBeUndefined()
    expect(result.failure?.message).toContain('Nope.')
    expect(result.failure?.message).not.toContain('cipherstash.com')
  })

  it('defaults a pre-cs_code 402 to the usage limit', async () => {
    // Deployments predating `cs_code` send a valid JSON body without it. The
    // status and absent key select the legacy default; `error` is not a
    // CipherStash taxonomy field and is deliberately ignored.
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        refusalBody('usage_limit_exceeded', undefined, 'Over the limit.'),
        'application/json',
      ),
    )

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
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

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('reads a bodyless 402 as the usage limit', async () => {
    // The one shape a 402 from CTS can take without being JSON: pre-`cs_code`
    // deployments sent no body at all, and that only ever meant this.
    vi.stubGlobal('fetch', ctsResponds(402, ''))

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(result.failure?.message).toContain('returned 402')
  })

  it('declines a 402 that did not come from CTS', async () => {
    // A gateway, WAF or proxy in front of CTS answers with a page of HTML, not
    // an `AuthorizeErrorBody`. Reporting that as a billing refusal sends the
    // caller to a billing page for something a retry would have cleared — and
    // on the Rust path it would sticky-cache a permanent denial. Mirrors
    // `classify_issuance_failure`, which declines a non-JSON 402 for the same
    // reason.
    const padding = '<html><body>'.padEnd(600, 'x')

    vi.stubGlobal('fetch', ctsResponds(402, padding))

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.type).toBe(EncryptionErrorTypes.CtsTokenError)
    expect(result.failure?.authCode).toBeUndefined()
    expect(result.failure?.message).not.toContain('dashboard.cipherstash.com')
    // Still quoted, but capped — a page of HTML is nobody's `Error.message`.
    expect(result.failure?.message).not.toContain(padding)
    expect(result.failure?.message).toContain('402')
  })

  it('declines a 402 whose `cs_code` is not a string', async () => {
    // Presence is decided on the raw value: `{"cs_code": 42}` must not read as
    // absent and fall through to the `error` arm, which is the inversion of
    // what that guard is for.
    vi.stubGlobal(
      'fetch',
      ctsResponds(
        402,
        JSON.stringify({
          error: 'usage_limit_exceeded',
          error_description: 'Over the limit.',
          cs_code: 42,
        }),
        'application/json',
      ),
    )

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.authCode).toBeUndefined()
    expect(result.failure?.message).toContain('Over the limit.')
  })
})

describe('identify(): other non-2xx statuses are not mislabelled', () => {
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

      const result = await new LockContext().identify('a-user-jwt')

      expect(result.failure?.type).toBe(EncryptionErrorTypes.CtsTokenError)
      expect(result.failure?.authCode).toBeUndefined()
      // The status and what the server actually said — the two things a
      // caller needs and neither of which survived before.
      expect(result.failure?.message).toContain(String(status))
      expect(result.failure?.message).toContain(body)
      // No billing remedy on a failure that is not a billing failure.
      expect(result.failure?.message).not.toContain('dashboard.cipherstash.com')
      expect(result.failure?.message).not.toContain('billing')
    })
  }

  it('survives an empty error body without trailing punctuation debris', async () => {
    vi.stubGlobal('fetch', ctsResponds(502, ''))

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.type).toBe(EncryptionErrorTypes.CtsTokenError)
    expect(result.failure?.message).toContain('502')
    expect(result.failure?.message).not.toMatch(/[:\s]$/)
  })
})

describe('identify(): the 2xx paths are unchanged', () => {
  it('still reports a 200 with no access token as exactly that', async () => {
    // The original message is correct HERE and nowhere else: a 200 whose body
    // has no token really is a malformed response worth a support ticket.
    vi.stubGlobal(
      'fetch',
      ctsResponds(200, JSON.stringify({ expiry: 1 }), 'application/json'),
    )

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.type).toBe(EncryptionErrorTypes.CtsTokenError)
    expect(result.failure?.message).toBe(
      'The response from the CipherStash API did not contain an access token. Please contact support.',
    )
    expect(result.failure?.authCode).toBeUndefined()
  })

  it('reports a 200 with an unparseable body as a failure, not a throw', async () => {
    vi.stubGlobal('fetch', ctsResponds(200, 'not json at all'))

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.type).toBe(EncryptionErrorTypes.CtsTokenError)
    expect(result.failure?.authCode).toBeUndefined()
  })

  it('still resolves a token on the happy path', async () => {
    vi.stubGlobal('fetch', ctsIssuesToken())

    const lockContext = new LockContext()
    const result = await lockContext.identify('a-user-jwt')

    expect(result.failure).toBeUndefined()
    expect(result.data).toBe(lockContext)

    const stored = await lockContext.getLockContext()
    expect(stored.data?.ctsToken).toEqual({
      accessToken: 'cts-token',
      expiry: 1_900_000_000,
    })
  })
})

describe('identify(): a transport failure is still a transport failure', () => {
  it('reports a rejected fetch with its own message and no auth code', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('fetch failed: ECONNREFUSED')
      }),
    )

    const result = await new LockContext().identify('a-user-jwt')

    expect(result.failure?.type).toBe(EncryptionErrorTypes.CtsTokenError)
    expect(result.failure?.message).toBe('fetch failed: ECONNREFUSED')
    expect(result.failure?.authCode).toBeUndefined()
  })
})
