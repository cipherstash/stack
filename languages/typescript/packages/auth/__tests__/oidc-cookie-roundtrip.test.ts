import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { cookieStore } from '../cookies.mjs'
import { MockCtsServer } from './helpers/mock-cts-server'

const { OidcFederationStrategy } =
  require('../index.js') as typeof import('../index')

const WORKSPACE_ID = 'ZVATKW3VHMFG27DY'
const WORKSPACE_CRN = `crn:ap-southeast-2.aws:${WORKSPACE_ID}`

let server: MockCtsServer
let savedHost: string | undefined

beforeEach(async () => {
  server = await MockCtsServer.start()
  savedHost = process.env.CS_CTS_HOST
  process.env.CS_CTS_HOST = server.baseUrl
})

afterEach(async () => {
  if (savedHost === undefined) {
    delete process.env.CS_CTS_HOST
  } else {
    process.env.CS_CTS_HOST = savedHost
  }
  await server.close()
})

/** Extract the `name=value` pair from a `Set-Cookie` header. */
function cookiePair(setCookie: string): string {
  return setCookie.split(';')[0]
}

/** A `Request` carrying the given `Cookie:` header (or none). */
function requestWith(cookie?: string): Request {
  return new Request('https://example.com/', {
    headers: cookie ? { cookie } : {},
  })
}

/** Unwrap a `createWithStore` Result, failing the test if it returned a failure. */
function mustCreateWithStore(
  ...args: Parameters<typeof OidcFederationStrategy.createWithStore>
): InstanceType<typeof OidcFederationStrategy> {
  const cr = OidcFederationStrategy.createWithStore(...args)
  if (cr.failure) {
    expect.unreachable(`createWithStore failed: ${cr.failure.type}`)
  }
  return cr.data
}

describe('OidcFederationStrategy + cookieStore round-trip', () => {
  it('writes the federated CTS token to a Set-Cookie header', async () => {
    server.mockAuthorizeEndpoint()
    const responseHeaders = new Headers()
    const store = cookieStore({ request: requestWith(), responseHeaders })

    const strategy = mustCreateWithStore(
      WORKSPACE_CRN,
      () => Promise.resolve('header.payload.signature'),
      store.load,
      store.save,
    )
    const r = await strategy.getToken()
    if (r.failure) {
      expect.unreachable(`getToken failed: ${r.failure.type}`)
    }

    expect(r.data.workspaceId).toBe(WORKSPACE_ID)
    const setCookie = responseHeaders.get('set-cookie')
    expect(setCookie).toBeTruthy()
    expect(setCookie).toMatch(/^cs_token=/)
  })

  it('reuses a cached token from the cookie without re-federating', async () => {
    // First request federates and writes the cookie.
    server.mockAuthorizeEndpoint()
    const firstHeaders = new Headers()
    const firstStore = cookieStore({
      request: requestWith(),
      responseHeaders: firstHeaders,
    })
    const first = mustCreateWithStore(
      WORKSPACE_CRN,
      () => Promise.resolve('header.payload.signature'),
      firstStore.load,
      firstStore.save,
    )
    await first.getToken()
    const cookie = cookiePair(firstHeaders.get('set-cookie')!)

    // Second request carries the cookie. Federation would fail (500) and
    // getJwt would throw — proving the token came from the cookie.
    server.clearMocks()
    server.mockAuthorizeEndpointError()
    const secondStore = cookieStore({
      request: requestWith(cookie),
      responseHeaders: new Headers(),
    })
    const second = mustCreateWithStore(
      WORKSPACE_CRN,
      () => Promise.reject(new Error('getJwt must not be called')),
      secondStore.load,
      secondStore.save,
    )

    const r = await second.getToken()
    if (r.failure) {
      expect.unreachable(`getToken failed: ${r.failure.type}`)
    }
    expect(r.data.workspaceId).toBe(WORKSPACE_ID)
  })

  it('re-federates when the cookie holds an expired token', async () => {
    // First request federates a token that is immediately expired (expiry 0).
    server.mockAuthorizeEndpoint(0)
    const firstHeaders = new Headers()
    const firstStore = cookieStore({
      request: requestWith(),
      responseHeaders: firstHeaders,
    })
    const first = mustCreateWithStore(
      WORKSPACE_CRN,
      () => Promise.resolve('header.payload.signature'),
      firstStore.load,
      firstStore.save,
    )
    await first.getToken()
    const cookie = cookiePair(firstHeaders.get('set-cookie')!)

    // Second request carries the expired cookie. getToken() must re-federate
    // — calling getJwt again — rather than serving the stale token.
    server.clearMocks()
    server.mockAuthorizeEndpoint()
    let getJwtCalls = 0
    const secondStore = cookieStore({
      request: requestWith(cookie),
      responseHeaders: new Headers(),
    })
    const second = mustCreateWithStore(
      WORKSPACE_CRN,
      () => {
        getJwtCalls += 1
        return Promise.resolve('header.payload.signature')
      },
      secondStore.load,
      secondStore.save,
    )

    const r = await second.getToken()
    if (r.failure) {
      expect.unreachable(`getToken failed: ${r.failure.type}`)
    }
    expect(r.data.workspaceId).toBe(WORKSPACE_ID)
    expect(getJwtCalls).toBe(1)
  })
})
