import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CS_TOKEN_HEADER,
  csAuthHeader,
  csFederate,
  csFederationMiddleware,
  csSanitizeHeaders,
  csTokenCookieName,
  decodeTokenHeader,
  encodeTokenHeader,
} from '../next.mjs'

// Mock the wasm strategy so these tests exercise the adapter's OWN wiring
// (cookie persistence, header encode/decode, warmed-token reads) deterministically
// and offline. The real federate-or-reuse + cookie round-trip against a CTS
// server is covered by `oidc-cookie-roundtrip.test.ts`. `vi.hoisted` lets the
// hoisted `vi.mock` factory reference these fns without a top-level await.
const { getToken, free, create } = vi.hoisted(() => ({
  getToken: vi.fn(),
  free: vi.fn(),
  create: vi.fn(),
}))

vi.mock('../wasm-inline.mjs', () => ({
  OidcFederationStrategy: {
    create: (
      crn: string,
      getJwt: () => unknown,
      options: { store?: { load(): unknown; save(json: string): unknown } },
    ) => create(crn, getJwt, options),
  },
}))

const WORKSPACE_ID = 'ZVATKW3VHMFG27DY'
const WORKSPACE_CRN = `crn:ap-southeast-2.aws:${WORKSPACE_ID}`

function tokenResult(overrides: Record<string, unknown> = {}) {
  return {
    token: 'header.payload.signature',
    subject: `CS|${WORKSPACE_ID}`,
    workspaceId: WORKSPACE_ID,
    issuer: 'https://cts.example.com',
    services: { zerokms: 'https://zerokms.example.com' },
    ...overrides,
  }
}

function requestWith(cookie?: string): Request {
  return new Request('https://example.com/', {
    headers: cookie ? { cookie } : {},
  })
}

/** A request carrying a client-forged warmed-token header (the attacker case). */
function requestWithForgedHeader(
  headerName = CS_TOKEN_HEADER,
  overrides: Record<string, unknown> = {
    token: 'forged',
    services: { zerokms: 'https://attacker.example.com' },
  },
): Request {
  return new Request('https://example.com/', {
    headers: {
      'x-unrelated': 'keep-me',
      [headerName]: encodeTokenHeader(tokenResult(overrides)),
    },
  })
}

beforeEach(() => {
  getToken.mockReset()
  free.mockReset()
  create.mockReset()
  // Default fake strategy: writes the token to the store (so cookie wiring is
  // exercised) and returns a Result-wrapped TokenResult. Both `create()` and
  // `getToken()` return `@byteslice/result` Results (`{ data }` on success),
  // matching the real wasm surface the adapter unwraps.
  create.mockImplementation(
    (
      _crn: string,
      _getJwt: () => unknown,
      options: { store?: { save(json: string): unknown } },
    ) => {
      getToken.mockImplementation(async () => {
        await options.store?.save(
          JSON.stringify({
            access_token: 'header.payload.signature',
            expires_at: Math.floor(Date.now() / 1000) + 3600,
          }),
        )
        return { data: tokenResult() }
      })
      return { data: { getToken, free } }
    },
  )
})

describe('csTokenCookieName', () => {
  it('is per-workspace', () => {
    expect(csTokenCookieName(WORKSPACE_ID)).toBe(`cs_token_${WORKSPACE_ID}`)
  })
})

describe('encode/decodeTokenHeader', () => {
  it('round-trips a TokenResult through the opaque header payload', () => {
    const r = tokenResult()
    const decoded = decodeTokenHeader(encodeTokenHeader(r))
    expect(decoded).toEqual(r)
  })

  it('produces a header-safe value (no base64 +/=/ chars)', () => {
    const v = encodeTokenHeader(tokenResult())
    expect(v).not.toMatch(/[+/=]/)
  })
})

describe('csFederate', () => {
  it('builds the strategy with the cookie-backed store and persists the token', async () => {
    const responseHeaders = new Headers()
    const result = await csFederate({
      request: requestWith(),
      responseHeaders,
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => 'jwt',
      baseUrl: 'https://cts.example.com',
      cookieName: csTokenCookieName(WORKSPACE_ID),
    })

    expect(result.workspaceId).toBe(WORKSPACE_ID)
    // baseUrl threaded through to the strategy.
    expect(create).toHaveBeenCalledWith(WORKSPACE_CRN, expect.any(Function), {
      store: expect.anything(),
      baseUrl: 'https://cts.example.com',
    })
    // The cookie was written under the per-workspace name.
    const setCookie = responseHeaders.get('set-cookie')
    expect(setCookie).toMatch(new RegExp(`^cs_token_${WORKSPACE_ID}=`))
    // wasm resources released.
    expect(free).toHaveBeenCalledOnce()
  })

  it('defaults the cookie name to cs_token_<workspaceId> from the CRN when omitted', async () => {
    const responseHeaders = new Headers()
    await csFederate({
      request: requestWith(),
      responseHeaders,
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => 'jwt',
      // cookieName intentionally omitted — must NOT collapse to `cs_token`.
    })
    expect(responseHeaders.get('set-cookie')).toMatch(
      new RegExp(`^cs_token_${WORKSPACE_ID}=`),
    )
  })

  it("throws the failure's error and still frees the strategy (finally path)", async () => {
    // Override the default fake so getToken resolves to a `{ failure }` Result —
    // the new-API failure mode. csFederate must unwrap it, throw the live
    // `failure.error`, and still run the try/finally's `free()`.
    create.mockImplementation(() => {
      getToken.mockResolvedValue({
        failure: {
          type: 'SERVER_ERROR',
          error: new Error('federation failed'),
        },
      })
      return { data: { getToken, free } }
    })

    await expect(
      csFederate({
        request: requestWith(),
        responseHeaders: new Headers(),
        workspaceCrn: WORKSPACE_CRN,
        getJwt: () => 'jwt',
      }),
    ).rejects.toThrow('federation failed')
    // free() still ran despite the throw.
    expect(free).toHaveBeenCalledOnce()
  })

  it('propagates a getToken rejection and still frees the strategy (wasm panic path)', async () => {
    // Distinct from the `{ failure }` domain-error path above: a genuine wasm
    // panic (unbranded error, or calling getToken after free) rejects the
    // promise rather than resolving to `{ failure }` — `settleGetToken` re-throws
    // it. The `await` must propagate the rejection while the finally still frees.
    create.mockImplementation(() => {
      getToken.mockRejectedValue(new Error('null pointer passed to rust'))
      return { data: { getToken, free } }
    })

    await expect(
      csFederate({
        request: requestWith(),
        responseHeaders: new Headers(),
        workspaceCrn: WORKSPACE_CRN,
        getJwt: () => 'jwt',
      }),
    ).rejects.toThrow('null pointer passed to rust')
    expect(free).toHaveBeenCalledOnce()
  })

  it("throws the failure's error when strategy creation fails (no free)", async () => {
    // `create()` itself can fail (e.g. INVALID_CRN) — it returns `{ failure }`
    // before any strategy is allocated, so csFederate throws without calling
    // free() (there's nothing to release).
    create.mockImplementation(() => ({
      failure: { type: 'INVALID_CRN', error: new Error('bad crn') },
    }))

    await expect(
      csFederate({
        request: requestWith(),
        responseHeaders: new Headers(),
        workspaceCrn: WORKSPACE_CRN,
        getJwt: () => 'jwt',
      }),
    ).rejects.toThrow('bad crn')
    expect(free).not.toHaveBeenCalled()
  })
})

describe('csFederationMiddleware', () => {
  it('returns the warmed token header alongside the result', async () => {
    const responseHeaders = new Headers()
    const { result, headerName, headerValue } = await csFederationMiddleware({
      request: requestWith(),
      responseHeaders,
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => 'jwt',
      cookieName: csTokenCookieName(WORKSPACE_ID),
    })

    expect(headerName).toBe(CS_TOKEN_HEADER)
    expect(decodeTokenHeader(headerValue)).toEqual(result)
    // Both caches populated: cookie (cross-request) + header (same-request).
    expect(responseHeaders.get('set-cookie')).toBeTruthy()
  })

  it('honours a custom header name', async () => {
    const { headerName } = await csFederationMiddleware({
      request: requestWith(),
      responseHeaders: new Headers(),
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => 'jwt',
      cookieName: csTokenCookieName(WORKSPACE_ID),
      headerName: 'x-warm',
    })
    expect(headerName).toBe('x-warm')
  })

  it('returns requestHeaders with the forged inbound header replaced by the minted one', async () => {
    // The forgery invariant lives in the library: a client-supplied
    // `x-cs-cts-token` must never survive into the render, even though the
    // freshly minted `set()` would overwrite it anyway on this (success) path.
    const { result, requestHeaders } = await csFederationMiddleware({
      request: requestWithForgedHeader(),
      responseHeaders: new Headers(),
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => 'jwt',
      cookieName: csTokenCookieName(WORKSPACE_ID),
    })

    // Downstream reads the real token, not the attacker's.
    const warmed = csAuthHeader(requestHeaders)
    expect((await warmed?.getToken())?.data).toEqual(result)
    expect((await warmed?.getToken())?.data?.services.zerokms).toBe(
      'https://zerokms.example.com',
    )
    // Unrelated inbound headers are preserved for the render.
    expect(requestHeaders.get('x-unrelated')).toBe('keep-me')
  })

  it('strips the forged header under a custom header name too', async () => {
    const { requestHeaders } = await csFederationMiddleware({
      request: requestWithForgedHeader('x-warm'),
      responseHeaders: new Headers(),
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => 'jwt',
      cookieName: csTokenCookieName(WORKSPACE_ID),
      headerName: 'x-warm',
    })
    expect(
      (await csAuthHeader(requestHeaders, { headerName: 'x-warm' })?.getToken())
        ?.data?.token,
    ).toBe('header.payload.signature')
  })
})

describe('csSanitizeHeaders', () => {
  it('deletes a client-forged warmed-token header and keeps the rest', () => {
    const sanitized = csSanitizeHeaders(requestWithForgedHeader())
    expect(sanitized.get(CS_TOKEN_HEADER)).toBeNull()
    expect(csAuthHeader(sanitized)).toBeNull()
    expect(sanitized.get('x-unrelated')).toBe('keep-me')
  })

  it('accepts a Headers as well as a Request', () => {
    const sanitized = csSanitizeHeaders(requestWithForgedHeader().headers)
    expect(csAuthHeader(sanitized)).toBeNull()
  })

  it('does not mutate the source headers', () => {
    const headers = requestWithForgedHeader().headers
    csSanitizeHeaders(headers)
    // Request headers are immutable in the fetch spec, so a delete on the source
    // would throw rather than silently strip — assert the clone is what changed.
    expect(headers.get(CS_TOKEN_HEADER)).not.toBeNull()
  })

  it('strips only the named header', () => {
    const request = new Request('https://example.com/', {
      headers: {
        [CS_TOKEN_HEADER]: encodeTokenHeader(tokenResult()),
        'x-warm': encodeTokenHeader(tokenResult()),
      },
    })
    const sanitized = csSanitizeHeaders(request, { headerName: 'x-warm' })
    expect(sanitized.get('x-warm')).toBeNull()
    expect(sanitized.get(CS_TOKEN_HEADER)).not.toBeNull()
  })
})

describe('csAuthHeader', () => {
  it('reads a warmed token from the request header into a no-federation strategy', async () => {
    const headers = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader(tokenResult()),
    })
    const strategy = csAuthHeader(headers)
    expect(strategy).not.toBeNull()
    expect(strategy?.requiresFederation).toBe(false)
    // Warmed strategy mirrors a real strategy: getToken() resolves a `{ data }`
    // Result, not a bare TokenResult.
    expect((await strategy?.getToken())?.data?.workspaceId).toBe(WORKSPACE_ID)
  })

  it('reads eagerly at construction (later header mutation is ignored)', async () => {
    const headers = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader(tokenResult({ token: 'first' })),
    })
    const strategy = csAuthHeader(headers)
    headers.set(
      CS_TOKEN_HEADER,
      encodeTokenHeader(tokenResult({ token: 'second' })),
    )
    expect((await strategy?.getToken())?.data?.token).toBe('first')
  })

  it('returns null when no warmed token is present (cold fallback)', () => {
    expect(csAuthHeader(new Headers())).toBeNull()
  })

  it('returns null on a malformed header rather than throwing', () => {
    const headers = new Headers({ [CS_TOKEN_HEADER]: 'not-valid-base64url!!' })
    expect(csAuthHeader(headers)).toBeNull()
  })

  it('rejects a structurally-incomplete TokenResult (spoof/partial payload)', () => {
    // Missing workspaceId/subject/issuer — decodes fine but isn't a TokenResult.
    const partial = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader({
        token: 'header.payload.signature',
      } as never),
    })
    expect(csAuthHeader(partial)).toBeNull()

    // services present but not a string→string map.
    const badServices = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader(
        tokenResult({ services: { zerokms: 123 } }) as never,
      ),
    })
    expect(csAuthHeader(badServices)).toBeNull()

    // services present but EMPTY — a federated token always has >=1 endpoint.
    const emptyServices = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader(tokenResult({ services: {} })),
    })
    expect(csAuthHeader(emptyServices)).toBeNull()

    // Field PRESENT but empty string — distinct from missing; must still reject
    // (isTokenResult's `.length === 0` branch). workspaceId is representative.
    const emptyField = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader(tokenResult({ workspaceId: '' })),
    })
    expect(csAuthHeader(emptyField)).toBeNull()
  })

  it('honours a custom header name', async () => {
    const headers = new Headers({ 'x-warm': encodeTokenHeader(tokenResult()) })
    expect(csAuthHeader(headers, { headerName: 'x-warm' })).not.toBeNull()
    expect(csAuthHeader(headers)).toBeNull()
  })
})
