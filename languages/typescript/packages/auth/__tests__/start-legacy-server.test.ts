import { beforeEach, describe, expect, it, vi } from 'vitest'
import { csTokenCookieName } from '../next.mjs'
import { csFederationMiddleware } from '../start.mjs'

// The pre-1.169 Start surface. `appendResponseHeader` arrived in
// `@tanstack/start-server-core` 1.169.41 (TanStack Start 1.169), and in the
// same release `getResponseHeaders()` became a read-only snapshot. Every Start
// from this entry's 1.132 floor up to 1.168 has neither: the one way to add a
// `Set-Cookie` without dropping the cookies already there is to append to the
// live `Headers` that `getResponseHeaders()` returns. The dev dependency is the
// current Start, so `start.test.ts` exercises the new primitive against the
// real thing; this file pins the fallback by presenting the adapter with the
// old surface — a server module with no `appendResponseHeader` and a
// `getResponseHeaders()` that returns the response's own mutable headers.
const { live, request } = vi.hoisted(() => ({
  live: new Headers(),
  request: { current: null as Request | null },
}))

vi.mock('@tanstack/react-start/server', () => ({
  getRequest: () => {
    if (!request.current) throw new Error('No StartEvent found')
    return request.current
  },
  getResponseHeaders: () => live,
  // Deliberately NOT a function. (vitest's mock proxy throws on an export the
  // factory leaves out, so the absence is spelled as an explicit undefined.)
  appendResponseHeader: undefined,
}))

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
const COOKIE = csTokenCookieName(WORKSPACE_ID)

beforeEach(() => {
  for (const name of [...new Set([...live.keys()])]) live.delete(name)
  request.current = new Request('https://example.com/_serverFn/loadSecret')
  getToken.mockReset()
  free.mockReset()
  create.mockReset()
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
        return {
          data: {
            token: 'header.payload.signature',
            subject: `CS|${WORKSPACE_ID}`,
            workspaceId: WORKSPACE_ID,
            issuer: 'https://cts.example.com',
            services: { zerokms: 'https://zerokms.example.com' },
          },
        }
      })
      return { data: { getToken, free } }
    },
  )
})

async function runServer(
  middleware: ReturnType<typeof csFederationMiddleware>,
) {
  const next = vi.fn(async (ctx?: { context?: unknown }) => ({
    context: ctx?.context,
  }))
  const server = middleware.options.server
  if (!server) throw new Error('middleware has no server half')
  // biome-ignore lint/suspicious/noExplicitAny: Start's full option bag is irrelevant here
  await server({ next, context: {}, method: 'GET' } as any)
  return next
}

describe('csFederationMiddleware on Start < 1.169 (no appendResponseHeader)', () => {
  it('appends the cookie to the live response headers, keeping existing cookies', async () => {
    live.append('set-cookie', '__session=clerk; Path=/; HttpOnly')

    const next = await runServer(
      csFederationMiddleware({
        workspaceCrn: WORKSPACE_CRN,
        getJwt: () => 'jwt',
      }),
    )

    expect(next).toHaveBeenCalledOnce()
    const cookies = live.getSetCookie()
    expect(cookies).toHaveLength(2)
    expect(cookies[0]).toBe('__session=clerk; Path=/; HttpOnly')
    expect(cookies[1]).toMatch(new RegExp(`^${COOKIE}=`))
  })

  it('reads the request from getRequest()', async () => {
    const stored = JSON.stringify({ access_token: 'cached', expires_at: 1 })
    request.current = new Request('https://example.com/', {
      headers: {
        cookie: `${COOKIE}=${Buffer.from(stored).toString('base64url')}`,
      },
    })
    let store: { load(): Promise<string | null> } | undefined
    create.mockImplementation(
      (
        _crn: string,
        _getJwt: () => unknown,
        options: { store?: { load(): Promise<string | null> } },
      ) => {
        store = options.store
        getToken.mockResolvedValue({
          data: {
            token: 't',
            subject: 's',
            workspaceId: WORKSPACE_ID,
            issuer: 'i',
            services: { zerokms: 'z' },
          },
        })
        return { data: { getToken, free } }
      },
    )

    await runServer(
      csFederationMiddleware({
        workspaceCrn: WORKSPACE_CRN,
        getJwt: () => 'jwt',
      }),
    )
    expect(await store?.load()).toBe(stored)
  })
})
