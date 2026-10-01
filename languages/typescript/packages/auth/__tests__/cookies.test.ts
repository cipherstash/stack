import { describe, expect, it } from 'vitest'
import { cookieStore } from '../cookies.mjs'

function makeRequest(cookieHeader?: string): Request {
  return new Request('https://example.com/', {
    headers: cookieHeader ? { cookie: cookieHeader } : {},
  })
}

function tokenJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    access_token: 'test-jwt',
    token_type: 'Bearer',
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    refresh_token: null,
    region: null,
    client_id: null,
    device_instance_id: null,
    ...overrides,
  })
}

function extractCookieValue(setCookie: string): string {
  // Set-Cookie format: "name=value; Path=/; ..."
  const firstPair = setCookie.split(';')[0]
  return firstPair.slice(firstPair.indexOf('=') + 1)
}

describe('cookieStore.load', () => {
  it('returns null when no cookie header is present', async () => {
    const store = cookieStore({
      request: makeRequest(),
      responseHeaders: new Headers(),
    })
    expect(await store.load()).toBeNull()
  })

  it("returns null when the cookie name isn't set", async () => {
    const store = cookieStore({
      request: makeRequest('other=value'),
      responseHeaders: new Headers(),
    })
    expect(await store.load()).toBeNull()
  })

  it('decodes the base64url-encoded value on the round trip', async () => {
    const responseHeaders = new Headers()
    const save = cookieStore({ request: makeRequest(), responseHeaders })
    const json = tokenJson()
    await save.save(json)
    const setCookie = responseHeaders.get('set-cookie')!

    const load = cookieStore({
      request: makeRequest(`cs_token=${extractCookieValue(setCookie)}`),
      responseHeaders: new Headers(),
    })
    expect(await load.load()).toBe(json)
  })

  it('ignores a corrupt base64url value (returns null)', async () => {
    const store = cookieStore({
      request: makeRequest('cs_token=not-valid-base64!@#'),
      responseHeaders: new Headers(),
    })
    expect(await store.load()).toBeNull()
  })
})

describe('cookieStore.save', () => {
  it('writes a Set-Cookie header on responseHeaders', async () => {
    const responseHeaders = new Headers()
    const store = cookieStore({ request: makeRequest(), responseHeaders })
    await store.save(tokenJson())
    expect(responseHeaders.get('set-cookie')).toMatch(/^cs_token=/)
  })

  it('base64url-encodes the value (no quotes in the cookie)', async () => {
    const responseHeaders = new Headers()
    const store = cookieStore({ request: makeRequest(), responseHeaders })
    await store.save(tokenJson())
    const setCookie = responseHeaders.get('set-cookie')!
    // RFC 6265 token-char range: no `"`, `,`, `;`, or `\` in the cookie value.
    const value = extractCookieValue(setCookie)
    expect(value).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('computes Max-Age from expires_at minus the safety margin', async () => {
    const responseHeaders = new Headers()
    const store = cookieStore({
      request: makeRequest(),
      responseHeaders,
      expirySafetyMarginSeconds: 30,
    })
    const expiresIn = 3600
    const expiresAt = Math.floor(Date.now() / 1000) + expiresIn
    await store.save(tokenJson({ expires_at: expiresAt }))
    const setCookie = responseHeaders.get('set-cookie')!
    const maxAgeMatch = setCookie.match(/Max-Age=(\d+)/)
    expect(maxAgeMatch).not.toBeNull()
    const maxAge = Number(maxAgeMatch![1])
    // Allow ±2s tolerance for the clock advancing during the test
    expect(maxAge).toBeGreaterThanOrEqual(expiresIn - 30 - 2)
    expect(maxAge).toBeLessThanOrEqual(expiresIn - 30)
  })

  it("omits Max-Age when expires_at can't be parsed", async () => {
    const responseHeaders = new Headers()
    const store = cookieStore({ request: makeRequest(), responseHeaders })
    await store.save('not valid json')
    const setCookie = responseHeaders.get('set-cookie')!
    expect(setCookie).not.toMatch(/Max-Age=/)
  })

  it('honours custom cookie attributes', async () => {
    const responseHeaders = new Headers()
    const store = cookieStore({
      request: makeRequest(),
      responseHeaders,
      name: 'custom_name',
      path: '/api',
      domain: 'example.com',
      secure: true,
      sameSite: 'Strict',
    })
    await store.save(tokenJson())
    const setCookie = responseHeaders.get('set-cookie')!
    expect(setCookie).toMatch(/^custom_name=/)
    expect(setCookie).toContain('Path=/api')
    expect(setCookie).toContain('Domain=example.com')
    expect(setCookie).toContain('Secure')
    expect(setCookie).toContain('SameSite=Strict')
  })

  it('HttpOnly is on by default; can be disabled', async () => {
    const onResponseHeaders = new Headers()
    const onStore = cookieStore({
      request: makeRequest(),
      responseHeaders: onResponseHeaders,
    })
    await onStore.save(tokenJson())
    expect(onResponseHeaders.get('set-cookie')).toContain('HttpOnly')

    const offResponseHeaders = new Headers()
    const offStore = cookieStore({
      request: makeRequest(),
      responseHeaders: offResponseHeaders,
      httpOnly: false,
    })
    await offStore.save(tokenJson())
    expect(offResponseHeaders.get('set-cookie')).not.toContain('HttpOnly')
  })

  it('rejects sameSite:None without secure (browsers drop the cookie)', () => {
    expect(() =>
      cookieStore({
        request: makeRequest(),
        responseHeaders: new Headers(),
        sameSite: 'None',
        secure: false,
      }),
    ).toThrow(/sameSite.*None.*requires.*secure/i)
  })

  it('allows sameSite:None when secure is set', async () => {
    const responseHeaders = new Headers()
    const store = cookieStore({
      request: makeRequest(),
      responseHeaders,
      sameSite: 'None',
      secure: true,
    })
    await store.save(tokenJson())
    const setCookie = responseHeaders.get('set-cookie')!
    expect(setCookie).toContain('SameSite=None')
    expect(setCookie).toContain('Secure')
  })
})
