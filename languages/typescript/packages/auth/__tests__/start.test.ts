import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  appendResponseHeader,
  createServerEntry,
  getResponseHeaders,
} from '@tanstack/react-start/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { csTokenCookieName } from '../next.mjs'
import { csFederateRequest, csFederationMiddleware } from '../start.mjs'

// Mock the wasm strategy exactly as `next.test.ts` does, so these tests
// exercise the Start adapter's OWN wiring — reading the request Start is
// handling, appending the cookie to Start's response, passing the warmed
// strategy through `next({ context })` — deterministically and offline. The
// real federate-or-reuse + cookie round-trip is covered by
// `oidc-cookie-roundtrip.test.ts`. What is NOT mocked is TanStack Start: the
// middleware is built with the real `createMiddleware`, and its server half
// runs inside a real `createServerEntry` request scope, so `getRequest()` and
// `appendResponseHeader()` are the production helpers, not stand-ins. (The
// pre-1.169 fallback, where `appendResponseHeader` does not exist, is covered
// by `start-legacy-server.test.ts`.)
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

type Store = { load(): Promise<string | null>; save(json: string): unknown }

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
  return new Request('https://example.com/_serverFn/loadSecret', {
    headers: cookie ? { cookie } : {},
  })
}

/**
 * Run `fn` the way Start runs a server function: inside a `createServerEntry`
 * request scope, where `getRequest()` / `appendResponseHeader()` resolve.
 * Returns what `fn` produced plus a snapshot of the response headers Start
 * will emit, taken inside the scope once `fn` has run (`createServerEntry`
 * establishes the scope; applying the header state to the final `Response` is
 * the job of Start's handler pipeline, which this test does not run).
 */
async function inRequest<T>(
  request: Request,
  fn: () => Promise<T>,
): Promise<{ value: T; responseHeaders: Headers }> {
  let value: T | undefined
  let responseHeaders: Headers | undefined
  let thrown: { error: unknown } | undefined
  const entry = createServerEntry({
    fetch: async () => {
      // `createServerEntry` turns a thrown error into an error Response; keep
      // the error itself so a test can assert on it.
      try {
        value = await fn()
      } catch (error) {
        thrown = { error }
      }
      responseHeaders = getResponseHeaders()
      return new Response('ok')
    },
  })
  await entry.fetch(request, {})
  if (thrown) throw thrown.error
  if (!responseHeaders) throw new Error('fetch did not run')
  return { value: value as T, responseHeaders }
}

/** Drive a function middleware's server half the way Start does. */
async function runServer(
  middleware: ReturnType<typeof csFederationMiddleware>,
) {
  const next = vi.fn(async (ctx?: { context?: unknown }) => ({
    context: ctx?.context,
  }))
  const server = middleware.options.server
  if (!server) throw new Error('middleware has no server half')
  const result = await server({
    data: undefined,
    context: {},
    next,
    method: 'GET',
    serverFnMeta: { id: 'test', name: 'loadSecret' },
    signal: new AbortController().signal,
    // biome-ignore lint/suspicious/noExplicitAny: Start's full generic option bag is irrelevant to the adapter
  } as any)
  return { next, result }
}

/** The `csAuth` the middleware passed to `next()`. */
function contextOf(next: ReturnType<typeof vi.fn>) {
  const call = next.mock.calls[0]?.[0] as
    | { context?: { csAuth?: unknown } }
    | undefined
  return call?.context
}

/** Every `Set-Cookie` Start will emit, as its own entry. */
function setCookies(headers: Headers): string[] {
  return headers.getSetCookie()
}

beforeEach(() => {
  getToken.mockReset()
  free.mockReset()
  create.mockReset()
  // Default fake strategy: writes the token to the store (so the cookie path is
  // exercised) and returns a Result-wrapped TokenResult, matching the real
  // wasm surface `csFederate` unwraps.
  create.mockImplementation(
    (_crn: string, _getJwt: () => unknown, options: { store?: Store }) => {
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

describe('csFederationMiddleware', () => {
  const options = {
    workspaceCrn: WORKSPACE_CRN,
    getJwt: () => 'jwt',
    baseUrl: 'https://cts.example.com',
  }

  it('builds a Start function middleware', () => {
    const middleware = csFederationMiddleware(options)
    // The real `createMiddleware({ type: 'function' }).server(...)` shape: an
    // `options` bag with the server half, which is what `createServerFn()
    // .middleware([...])` executes. Nothing is a request header.
    expect(typeof middleware.options.server).toBe('function')
    expect(middleware.options.client).toBeUndefined()
  })

  it('passes the warmed strategy to the handler through next({ context })', async () => {
    const middleware = csFederationMiddleware(options)
    const { value, responseHeaders } = await inRequest(requestWith(), () =>
      runServer(middleware),
    )

    expect(value.next).toHaveBeenCalledOnce()
    const context = contextOf(value.next)
    expect(context).toEqual({ csAuth: expect.any(Object) })
    const csAuth = context?.csAuth as {
      requiresFederation: boolean
      getToken(): Promise<{ data?: unknown }>
      free(): void
    }
    // A drop-in for a real strategy: no federation needed, Result-returning
    // getToken() resolving the federated token, releasable.
    expect(csAuth.requiresFederation).toBe(false)
    expect((await csAuth.getToken()).data).toEqual(tokenResult())
    expect(typeof csAuth.free).toBe('function')
    // next()'s result is what the middleware returns, so Start sees it.
    expect(value.result).toEqual({ context: { csAuth } })

    // The cross-request cache: the refreshed cookie reached Start's response.
    const cookies = setCookies(responseHeaders)
    expect(cookies).toHaveLength(1)
    expect(cookies[0]).toMatch(new RegExp(`^${COOKIE}=`))
    expect(cookies[0]).toMatch(/HttpOnly/)
    // baseUrl threaded through to the strategy; wasm resources released.
    expect(create).toHaveBeenCalledWith(WORKSPACE_CRN, expect.any(Function), {
      store: expect.anything(),
      baseUrl: 'https://cts.example.com',
    })
    expect(free).toHaveBeenCalledOnce()
  })

  it('reads the token cookie from the request Start is handling', async () => {
    // The store is built over `getRequest()`: a cookie on the inbound request
    // must be what `load()` hands the strategy for reuse.
    const stored = JSON.stringify({ access_token: 'cached', expires_at: 1 })
    const encoded = Buffer.from(stored).toString('base64url')
    let store: Store | undefined
    create.mockImplementation(
      (_crn: string, _getJwt: () => unknown, options: { store?: Store }) => {
        store = options.store
        getToken.mockResolvedValue({ data: tokenResult() })
        return { data: { getToken, free } }
      },
    )

    await inRequest(requestWith(`${COOKIE}=${encoded}; other=1`), () =>
      runServer(csFederationMiddleware(options)),
    )
    expect(await store?.load()).toBe(stored)
  })

  it('appends the cookie without dropping cookies already on the response', async () => {
    // Clerk (and Start itself) set cookies on the same response. The adapter
    // must APPEND its Set-Cookie: `setResponseHeader(name, [..])` deletes the
    // name first and `setResponseHeaders()` sets the first value per name, so
    // either would silently drop the session cookie.
    const middleware = csFederationMiddleware(options)
    const { responseHeaders } = await inRequest(requestWith(), async () => {
      appendResponseHeader('set-cookie', '__session=clerk; Path=/; HttpOnly')
      return runServer(middleware)
    })

    const cookies = setCookies(responseHeaders)
    expect(cookies).toHaveLength(2)
    expect(cookies[0]).toBe('__session=clerk; Path=/; HttpOnly')
    expect(cookies[1]).toMatch(new RegExp(`^${COOKIE}=`))
  })

  it('asks getJwt on every call, inside the request scope', async () => {
    // The strategy calls `getJwt` per `getToken()`; the adapter passes the
    // caller's function through untouched so Clerk's `auth()` (which reads
    // request-scoped storage) works from it.
    const getJwt = vi.fn(() => 'jwt')
    await inRequest(requestWith(), () =>
      runServer(csFederationMiddleware({ ...options, getJwt })),
    )
    expect(create).toHaveBeenCalledWith(
      WORKSPACE_CRN,
      getJwt,
      expect.anything(),
    )
  })

  it("throws the failure's error by default (signed out / federation failed)", async () => {
    create.mockImplementation(() => {
      getToken.mockResolvedValue({
        failure: {
          type: 'SERVER_ERROR',
          error: new Error('federation failed'),
        },
      })
      return { data: { getToken, free } }
    })
    const middleware = csFederationMiddleware(options)
    const next = vi.fn()

    await expect(
      inRequest(requestWith(), async () => {
        const server = middleware.options.server
        if (!server) throw new Error('no server half')
        // biome-ignore lint/suspicious/noExplicitAny: see runServer
        return server({ next, context: {}, method: 'GET' } as any)
      }),
    ).rejects.toThrow('federation failed')
    expect(next).not.toHaveBeenCalled()
    expect(free).toHaveBeenCalledOnce()
  })

  it('passes csAuth: null instead when onError is "null"', async () => {
    create.mockImplementation(() => {
      getToken.mockResolvedValue({
        failure: {
          type: 'SERVER_ERROR',
          error: new Error('federation failed'),
        },
      })
      return { data: { getToken, free } }
    })
    const middleware = csFederationMiddleware({ ...options, onError: 'null' })
    const { value, responseHeaders } = await inRequest(requestWith(), () =>
      runServer(middleware),
    )

    expect(value.next).toHaveBeenCalledOnce()
    expect(contextOf(value.next)).toEqual({ csAuth: null })
    // Nothing was federated, so nothing was cached.
    expect(setCookies(responseHeaders)).toEqual([])
  })

  it('treats a getJwt that throws (the signed-out case) the same way', async () => {
    // With Clerk, a signed-out request has no JWT; the documented wiring throws
    // from getJwt. The fake strategy surfaces that as a getToken rejection.
    create.mockImplementation((_crn: string, getJwt: () => unknown) => {
      getToken.mockImplementation(async () => {
        getJwt()
        return { data: tokenResult() }
      })
      return { data: { getToken, free } }
    })
    const getJwt = () => {
      throw new Error('signed out')
    }

    await expect(
      inRequest(requestWith(), () =>
        runServer(csFederationMiddleware({ ...options, getJwt })),
      ),
    ).rejects.toThrow('signed out')

    const { value } = await inRequest(requestWith(), () =>
      runServer(
        csFederationMiddleware({ ...options, getJwt, onError: 'null' }),
      ),
    )
    expect(contextOf(value.next)).toEqual({ csAuth: null })
  })

  it('rejects an unknown onError when the middleware is built, not on the first request', () => {
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately off-type
      csFederationMiddleware({ ...options, onError: 'swallow' as any }),
    ).toThrow(TypeError)
  })

  it('fails outside a Start request scope rather than federating blind', async () => {
    // No `createServerEntry` around it: `getRequest()` has no request to read.
    const middleware = csFederationMiddleware(options)
    await expect(runServer(middleware)).rejects.toThrow()
    expect(create).not.toHaveBeenCalled()
  })
})

describe('csFederateRequest', () => {
  it('returns the token and a warmed strategy, writing the cookie to the given headers', async () => {
    const responseHeaders = new Headers()
    const { result, strategy } = await csFederateRequest({
      request: requestWith(),
      responseHeaders,
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => 'jwt',
    })

    expect(result).toEqual(tokenResult())
    expect(strategy.requiresFederation).toBe(false)
    expect((await strategy.getToken()).data).toEqual(result)
    expect(responseHeaders.getSetCookie()[0]).toMatch(new RegExp(`^${COOKIE}=`))
    expect(free).toHaveBeenCalledOnce()
  })

  it('throws on failure like csFederate', async () => {
    create.mockImplementation(() => ({
      failure: { type: 'INVALID_CRN', error: new Error('bad crn') },
    }))
    await expect(
      csFederateRequest({
        request: requestWith(),
        responseHeaders: new Headers(),
        workspaceCrn: WORKSPACE_CRN,
        getJwt: () => 'jwt',
      }),
    ).rejects.toThrow('bad crn')
  })
})

// ---------------------------------------------------------------------------
// Type surface. vitest never runs tsc, so without this a `start.d.mts` whose
// `@tanstack/react-start` import stopped resolving — or whose middleware type
// drifted from what `createMiddleware().server()` returns — would pass every
// runtime test above while every consumer lost `context.csAuth`'s type. Like
// `consumer-typecheck.test.ts`, this type-checks a consumer by package name
// through the `exports` map; unlike it, the consumer is ESM (`.mts`) and is
// checked under both resolutions a Start app uses, because TanStack Start is
// ESM-only and a CommonJS-typed `.d.ts` cannot even resolve it under Node16.
// ---------------------------------------------------------------------------

const packageDir = join(__dirname, '..')
const tscBin = require.resolve('typescript/bin/tsc')

const CONSUMER = `
import { createMiddleware, createServerFn, createStart } from "@tanstack/react-start";
import {
  csFederateRequest,
  csFederationMiddleware,
  type CsAuthContext,
  type CsFederationMiddleware,
  type WarmedAuthStrategy,
} from "@cipherstash/auth/start";

const strict = csFederationMiddleware({ workspaceCrn: "crn:r:w", getJwt: () => "jwt" });
const lenient = csFederationMiddleware({
  workspaceCrn: "crn:r:w",
  getJwt: async () => "jwt",
  onError: "null",
});

// The declared type is exactly what createMiddleware().server() produces, in
// both directions — so the middleware composes with hand-written ones.
const handWritten = createMiddleware({ type: "function" }).server(({ next }) =>
  next({ context: { csAuth: null as unknown as WarmedAuthStrategy } }),
);
const a: CsFederationMiddleware<CsAuthContext> = handWritten;
const b: typeof handWritten = strict;
void a; void b;

export const loadSecret = createServerFn({ method: "GET" })
  .middleware([strict])
  .handler(async ({ context }) => {
    const strategy: WarmedAuthStrategy = context.csAuth;
    const result = await strategy.getToken();
    return result.failure ? null : result.data.workspaceId;
  });

export const maybeSignedOut = createServerFn()
  .middleware([lenient])
  .handler(async ({ context }) => {
    // @ts-expect-error csAuth may be null under onError: "null"
    const strategy: WarmedAuthStrategy = context.csAuth;
    void strategy;
    return context.csAuth === null;
  });

export const startInstance = createStart(() => ({ functionMiddleware: [lenient] }));

export async function handler(request: Request) {
  const responseHeaders = new Headers();
  const { result, strategy } = await csFederateRequest({
    request,
    responseHeaders,
    workspaceCrn: "crn:r:w",
    getJwt: () => "jwt",
  });
  const workspaceId: string = result.workspaceId;
  const requiresFederation: false = strategy.requiresFederation;
  void workspaceId; void requiresFederation;
}
`

// A consumer that must NOT compile: csAuth is a strategy, not a string. Proves
// the harness goes red when types are wrong rather than only green when right.
const BROKEN_CONSUMER = `
import { createServerFn } from "@tanstack/react-start";
import { csFederationMiddleware } from "@cipherstash/auth/start";

const strict = csFederationMiddleware({ workspaceCrn: "crn:r:w", getJwt: () => "jwt" });
export const fn = createServerFn()
  .middleware([strict])
  .handler(async ({ context }) => {
    const s: string = context.csAuth;
    return s;
  });
`

type Resolution = 'Node16' | 'bundler'

/**
 * A scratch project whose `node_modules` links `@cipherstash/auth` to this
 * package and `@tanstack` to the package's own install, so both the consumer
 * and `start.d.mts` resolve TanStack Start the way a real install does.
 */
function scratchProject(): string {
  const dir = mkdtempSync(join(tmpdir(), 'cs-auth-start-tscheck-'))
  mkdirSync(join(dir, 'node_modules', '@cipherstash'), { recursive: true })
  symlinkSync(packageDir, join(dir, 'node_modules', '@cipherstash', 'auth'))
  symlinkSync(
    join(packageDir, 'node_modules', '@tanstack'),
    join(dir, 'node_modules', '@tanstack'),
  )
  return dir
}

function tsc(dir: string, config: object): { ok: boolean; output: string } {
  writeFileSync(join(dir, 'tsconfig.json'), JSON.stringify(config))
  try {
    const output = execFileSync(
      process.execPath,
      [tscBin, '-p', join(dir, 'tsconfig.json')],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    )
    return { ok: true, output }
  } catch (err) {
    const e = err as { stdout?: Buffer | string; stderr?: Buffer | string }
    return { ok: false, output: `${e.stdout ?? ''}${e.stderr ?? ''}` }
  }
}

function typecheckConsumer(source: string, moduleResolution: Resolution) {
  const dir = scratchProject()
  writeFileSync(join(dir, 'consumer.mts'), source)
  return tsc(dir, {
    compilerOptions: {
      target: 'ES2022',
      module: moduleResolution === 'Node16' ? 'Node16' : 'ESNext',
      moduleResolution,
      strict: true,
      esModuleInterop: true,
      // What a Start app sets: library typings (React's, Node's) are not
      // checked. The declaration files themselves are checked below.
      skipLibCheck: true,
      noEmit: true,
    },
    files: ['consumer.mts'],
  })
}

describe('consumer typecheck (@cipherstash/auth/start)', () => {
  for (const resolution of ['Node16', 'bundler'] as const) {
    it(`a Start consumer type-checks under moduleResolution ${resolution}`, () => {
      const { ok, output } = typecheckConsumer(CONSUMER, resolution)
      expect(ok, `tsc reported type errors:\n${output}`).toBe(true)
    })

    it(`rejects a consumer that misreads context.csAuth under ${resolution} (guard has teeth)`, () => {
      const { ok, output } = typecheckConsumer(BROKEN_CONSUMER, resolution)
      expect(ok, 'tsc should reject a mistyped consumer').toBe(false)
      expect(output).toMatch(/TS2322/)
    })
  }

  it('the /start declaration files type-check with skipLibCheck off', () => {
    // `skipLibCheck: true` above would also hide an error INSIDE start.d.mts —
    // an unresolved import there degrades to `any` silently. Check the
    // declarations directly, keeping only diagnostics raised in this package's
    // own files: TanStack's typings reference `react` and `node:` modules whose
    // `@types` this package does not install, and that noise is theirs.
    const dir = scratchProject()
    const { output } = tsc(dir, {
      compilerOptions: {
        target: 'ES2022',
        module: 'Node16',
        moduleResolution: 'Node16',
        strict: true,
        skipLibCheck: false,
        noEmit: true,
      },
      files: [
        'node_modules/@cipherstash/auth/start.d.mts',
        'node_modules/@cipherstash/auth/warmed.d.ts',
        'node_modules/@cipherstash/auth/next.d.ts',
      ],
    })
    const own = output
      .split('\n')
      .filter((line) => /\): error TS\d+/.test(line))
      .filter((line) => !line.includes('node_modules/.pnpm/'))
    expect(own, `own-file diagnostics:\n${own.join('\n')}`).toEqual([])
  })
})

describe('publish contract (npm pack)', () => {
  it('packs the /start entry and the shared warmed-strategy module', () => {
    // `start.mjs` imports `./warmed.mjs` and `start.d.mts` imports
    // `./warmed.d.ts`; a `files` allowlist that forgot either would publish an
    // entry that dangles on a missing file.
    const out = execFileSync('npm', ['pack', '--json', '--dry-run'], {
      cwd: packageDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const packed = (
      JSON.parse(out) as Array<{ files: Array<{ path: string }> }>
    )[0].files.map((f) => f.path)
    expect(packed).toEqual(
      expect.arrayContaining([
        'start.mjs',
        'start.d.mts',
        'warmed.mjs',
        'warmed.d.ts',
      ]),
    )
  })
})
