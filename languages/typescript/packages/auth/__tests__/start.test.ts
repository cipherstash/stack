import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createMiddleware } from '@tanstack/react-start'
import {
  createServerEntry,
  getResponseHeaders,
  setCookie,
} from '@tanstack/react-start/server'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { csTokenCookieName } from '../next.mjs'
import { csFederateCurrent, csFederateRequest } from '../start.mjs'
import {
  create,
  type FakeStore,
  failFederation,
  free,
  getToken,
  installFakeStrategy,
  storedTokenJson,
  tokenResult,
  WORKSPACE_CRN,
  WORKSPACE_ID,
} from './helpers/fake-federation'
import {
  packageDir,
  packedFiles,
  removeScratchDirs,
  runTsc,
  scratchDir,
} from './helpers/tsc-consumer'

// The wasm strategy is the shared fake; TanStack Start is NOT mocked. Every
// test below runs inside a real `createServerEntry` request scope, so
// `getRequest()`, `getCookie()` and `setCookie()` are the production helpers,
// and what is asserted about the response is what Start will emit.
vi.mock('../wasm-inline.mjs', async () =>
  (await import('./helpers/fake-federation')).wasmInlineMock(),
)

const COOKIE = csTokenCookieName(WORKSPACE_ID)

const options = {
  workspaceCrn: WORKSPACE_CRN,
  getJwt: () => 'jwt',
  baseUrl: 'https://cts.example.com',
}

function requestWith(cookie?: string): Request {
  return new Request('https://example.com/_serverFn/loadSecret', {
    headers: cookie ? { cookie } : {},
  })
}

/**
 * Run `fn` the way Start runs a server function: inside a `createServerEntry`
 * request scope. Returns what `fn` produced plus the `Set-Cookie` values Start
 * will emit, read inside the scope once `fn` has run (`createServerEntry`
 * establishes the scope; applying the header state to the final `Response` is
 * the job of Start's handler pipeline, which this test does not run).
 */
async function inRequest<T>(
  request: Request,
  fn: () => Promise<T>,
): Promise<{ value: T; cookies: string[] }> {
  let value: T | undefined
  let cookies: string[] | undefined
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
      cookies = getResponseHeaders().getSetCookie()
      return new Response('ok')
    },
  })
  await entry.fetch(request, {})
  if (thrown) throw thrown.error
  if (!cookies) throw new Error('fetch did not run')
  return { value: value as T, cookies }
}

beforeEach(installFakeStrategy)
afterAll(removeScratchDirs)

describe('csFederateCurrent', () => {
  it('returns the federated token as a warmed strategy and caches it in the cookie', async () => {
    const { value: strategy, cookies } = await inRequest(requestWith(), () =>
      csFederateCurrent(options),
    )

    // A drop-in for a real strategy: no federation needed, Result-returning
    // getToken() resolving the federated token, releasable.
    expect(strategy.requiresFederation).toBe(false)
    expect((await strategy.getToken()).data).toEqual(tokenResult())
    expect(typeof strategy.free).toBe('function')

    // The cross-request cache, written through Start's own setCookie.
    expect(cookies).toHaveLength(1)
    expect(cookies[0]).toMatch(new RegExp(`^${COOKIE}=[A-Za-z0-9_-]+;`))
    expect(cookies[0]).toMatch(/Path=\//)
    expect(cookies[0]).toMatch(/HttpOnly/)
    expect(cookies[0]).toMatch(/Secure/)
    expect(cookies[0]).toMatch(/SameSite=Lax/)
    expect(cookies[0]).toMatch(/Max-Age=35\d\d/)
    // baseUrl threaded through to the strategy; wasm resources released.
    expect(create).toHaveBeenCalledWith(WORKSPACE_CRN, expect.any(Function), {
      store: expect.anything(),
      baseUrl: 'https://cts.example.com',
    })
    expect(free).toHaveBeenCalledOnce()
  })

  it('honours the cookie options', async () => {
    const { cookies } = await inRequest(requestWith(), () =>
      csFederateCurrent({
        ...options,
        cookieName: 'custom',
        secure: false,
        sameSite: 'Strict',
      }),
    )
    expect(cookies[0]).toMatch(/^custom=/)
    expect(cookies[0]).not.toMatch(/Secure/)
    expect(cookies[0]).toMatch(/SameSite=Strict/)
  })

  it('reads the token cookie from the request Start is handling', async () => {
    // A cookie on the inbound request must be what `load()` hands the strategy
    // for reuse — read through Start's getCookie, next to unrelated cookies.
    const stored = storedTokenJson()
    const encoded = Buffer.from(stored).toString('base64url')
    let loaded: string | null | undefined
    create.mockImplementation(
      (_crn: string, _getJwt: unknown, o: { store: FakeStore }) => {
        getToken.mockImplementation(async () => {
          loaded = await o.store.load()
          return { data: tokenResult() }
        })
        return { data: { getToken, free } }
      },
    )

    const { cookies } = await inRequest(
      requestWith(`other=1; ${COOKIE}=${encoded}; __session=clerk`),
      () => csFederateCurrent(options),
    )
    expect(loaded).toBe(stored)
    // A reuse writes nothing.
    expect(cookies).toEqual([])
  })

  it('keeps the cookies already on the response', async () => {
    // Clerk (and Start itself) set cookies on the same response. Writing the
    // token cookie must not drop them.
    const { cookies } = await inRequest(requestWith(), async () => {
      setCookie('__session', 'clerk', { httpOnly: true, path: '/' })
      return csFederateCurrent(options)
    })

    expect(cookies).toHaveLength(2)
    expect(cookies[0]).toMatch(/^__session=clerk;/)
    expect(cookies[1]).toMatch(new RegExp(`^${COOKIE}=`))
  })

  it('slots into a middleware the app declares, passing context.csAuth', async () => {
    // The documented wiring: the app writes the createMiddleware().server()
    // chain (so Start's compiler can strip it from the client bundle) and calls
    // csFederateCurrent inside it.
    const middleware = createMiddleware({ type: 'function' }).server(
      async ({ next }) => {
        const csAuth = await csFederateCurrent(options)
        return next({ context: { csAuth } })
      },
    )
    const next = vi.fn(async (ctx?: { context?: unknown }) => ({
      context: ctx?.context,
    }))

    await inRequest(requestWith(), async () => {
      const server = middleware.options.server
      if (!server) throw new Error('middleware has no server half')
      // biome-ignore lint/suspicious/noExplicitAny: Start's full option bag is irrelevant here
      return server({ next, context: {}, method: 'GET' } as any)
    })

    expect(next).toHaveBeenCalledOnce()
    const context = next.mock.calls[0][0]?.context as {
      csAuth: { getToken(): Promise<{ data?: unknown }> }
    }
    expect((await context.csAuth.getToken()).data).toEqual(tokenResult())
  })

  describe('sharing one federation per request', () => {
    it('federates once for every caller in a request', async () => {
      // A server render calls several server functions in ONE request, each
      // running the middleware. They must share one exchange and one cookie.
      const { value, cookies } = await inRequest(requestWith(), async () => {
        const first = await csFederateCurrent(options)
        const [second, third] = await Promise.all([
          csFederateCurrent(options),
          csFederateCurrent({ ...options, onError: 'null' }),
        ])
        return [first, second, third]
      })

      expect(create).toHaveBeenCalledOnce()
      expect(getToken).toHaveBeenCalledOnce()
      expect(cookies).toHaveLength(1)
      for (const strategy of value) {
        expect((await strategy?.getToken())?.data).toEqual(tokenResult())
      }
    })

    it('federates again for the next request', async () => {
      await inRequest(requestWith(), () => csFederateCurrent(options))
      await inRequest(requestWith(), () => csFederateCurrent(options))
      expect(create).toHaveBeenCalledTimes(2)
    })

    it('keeps different workspaces and cookies apart within a request', async () => {
      const { cookies } = await inRequest(requestWith(), async () => {
        await csFederateCurrent(options)
        await csFederateCurrent({ ...options, cookieName: 'other' })
        await csFederateCurrent({
          ...options,
          workspaceCrn: 'crn:ap-southeast-2.aws:OTHERWORKSPACE00',
        })
      })
      expect(create).toHaveBeenCalledTimes(3)
      expect(cookies.map((c) => c.split('=')[0])).toEqual([
        COOKIE,
        'other',
        csTokenCookieName('OTHERWORKSPACE00'),
      ])
    })

    it('rejects conflicting cookie settings instead of silently keeping the first', async () => {
      // A later caller joins the federation already started, so its settings
      // are never applied. Asking for a Secure cookie and getting the
      // non-Secure one an earlier caller wrote must not pass silently — and
      // must not read as "signed out" under onError: "null".
      const { cookies } = await inRequest(requestWith(), async () => {
        await csFederateCurrent({ ...options, secure: false })
        await expect(
          csFederateCurrent({ ...options, secure: true, onError: 'null' }),
        ).rejects.toThrow(/already writing the cookie .* secure: false/)
        await expect(
          csFederateCurrent({ ...options, secure: false, sameSite: 'Strict' }),
        ).rejects.toThrow(TypeError)
        // The defaults count: omitted means secure: true, sameSite: "Lax".
        await expect(csFederateCurrent(options)).rejects.toThrow(TypeError)
        // Same settings, spelled out or not, still share.
        await csFederateCurrent({ ...options, secure: false, sameSite: 'Lax' })
      })
      expect(create).toHaveBeenCalledOnce()
      expect(cookies).toHaveLength(1)
      expect(cookies[0]).not.toMatch(/Secure/)
    })

    it('checks cookie settings by the cookie that is written, not by how it was named', async () => {
      // The default cookie name left out and the same name spelled out are one
      // cookie: they share a federation, and may not disagree about it.
      await inRequest(requestWith(), async () => {
        await csFederateCurrent({ ...options, secure: false })
        await expect(
          csFederateCurrent({ ...options, cookieName: COOKIE, secure: true }),
        ).rejects.toThrow(new RegExp(`already writing the cookie "${COOKIE}"`))
        await csFederateCurrent({
          ...options,
          cookieName: COOKIE,
          secure: false,
        })
      })
      expect(create).toHaveBeenCalledOnce()
    })

    it('checks cookie settings across federations that share a cookie', async () => {
      // Two CTS hosts for one workspace are two federations, but one cookie.
      const elsewhere = { ...options, baseUrl: 'https://cts.other.example' }
      const { cookies } = await inRequest(requestWith(), async () => {
        await csFederateCurrent({ ...options, sameSite: 'Strict' })
        await expect(
          csFederateCurrent({ ...elsewhere, onError: 'null' }),
        ).rejects.toThrow(/already writing the cookie .* sameSite: "Strict"/)
        // With the same settings the second federation is allowed.
        await csFederateCurrent({ ...elsewhere, sameSite: 'Strict' })
      })
      expect(create).toHaveBeenCalledTimes(2)
      expect(cookies.every((c) => /SameSite=Strict/.test(c))).toBe(true)
    })

    it("forgets a cookie's settings with the failure that set them", async () => {
      failFederation()
      await inRequest(requestWith(), async () => {
        await csFederateCurrent({ ...options, secure: false, onError: 'null' })
        installFakeStrategy()
        // Nothing was written, so nothing is in conflict.
        await csFederateCurrent({ ...options, secure: true })
      })
    })

    it('does not remember a failure', async () => {
      // A failed exchange may be transient: the next caller in the same
      // request tries again instead of inheriting the error.
      failFederation()
      const { value } = await inRequest(requestWith(), async () => {
        const first = await csFederateCurrent({ ...options, onError: 'null' })
        installFakeStrategy()
        const second = await csFederateCurrent(options)
        return { first, second }
      })
      expect(value.first).toBeNull()
      expect((await value.second.getToken()).data).toEqual(tokenResult())
    })
  })

  describe('onError', () => {
    it("throws the failure's error by default (signed out / federation failed)", async () => {
      failFederation()
      await expect(
        inRequest(requestWith(), () => csFederateCurrent(options)),
      ).rejects.toThrow('federation failed')
      expect(free).toHaveBeenCalledOnce()
    })

    it('resolves null instead when onError is "null", and writes no cookie', async () => {
      failFederation()
      const { value, cookies } = await inRequest(requestWith(), () =>
        csFederateCurrent({ ...options, onError: 'null' }),
      )
      expect(value).toBeNull()
      expect(cookies).toEqual([])
    })

    it('treats a getJwt that throws (the signed-out case) the same way', async () => {
      // With Clerk, a signed-out request has no JWT; the documented wiring
      // throws from getJwt. The fake strategy surfaces that as a rejection.
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
          csFederateCurrent({ ...options, getJwt }),
        ),
      ).rejects.toThrow('signed out')
      const { value } = await inRequest(requestWith(), () =>
        csFederateCurrent({ ...options, getJwt, onError: 'null' }),
      )
      expect(value).toBeNull()
    })

    it('never folds misuse into null', async () => {
      // An unknown onError is a bug, not "signed out"...
      await expect(
        inRequest(requestWith(), () =>
          // biome-ignore lint/suspicious/noExplicitAny: deliberately off-type
          csFederateCurrent({ ...options, onError: 'swallow' as any }),
        ),
      ).rejects.toThrow(TypeError)
      // ...and so is calling it outside a Start request scope, where there is
      // no request to read: it must not federate blind or resolve null.
      await expect(
        csFederateCurrent({ ...options, onError: 'null' }),
      ).rejects.toThrow(/StartEvent|server runtime/)
      expect(create).not.toHaveBeenCalled()
    })

    it('rejects a request, responseHeaders or jar instead of reporting signed out', async () => {
      // The types exclude these, but a `csFederate` options object held in a
      // variable is structurally assignable. Forwarded, they would collide
      // with Start's jar on every call — and onError: "null" would turn that
      // into "signed out" for every user.
      const explicit = {
        ...options,
        request: requestWith(),
        responseHeaders: new Headers(),
      }
      for (const extra of [
        explicit,
        { ...options, request: requestWith() },
        { ...options, jar: { get: () => undefined, set: () => {} } },
      ]) {
        await expect(
          inRequest(requestWith(), () =>
            // biome-ignore lint/suspicious/noExplicitAny: deliberately off-type
            csFederateCurrent({ ...extra, onError: 'null' } as any),
          ),
        ).rejects.toThrow(/are not options here/)
      }
      expect(create).not.toHaveBeenCalled()
    })
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
// Type surface. vitest never runs tsc, so without this a broken `start.d.mts`
// would pass every runtime test above while consumers lost `context.csAuth`'s
// type. The consumer is ESM (`.mts`) and is checked under both resolutions a
// Start app uses; it writes the documented wiring, so the test also proves the
// strategy's type reaches a server function's handler through a middleware the
// app declares itself.
// ---------------------------------------------------------------------------

const CONSUMER = `
import { createMiddleware, createServerFn, createStart } from "@tanstack/react-start";
import { cookieStore, type CookieJar } from "@cipherstash/auth/cookies";
import { csFederate, type CsFederateOptions } from "@cipherstash/auth/next";
import {
  csFederateCurrent,
  csFederateRequest,
  type CsFederateCurrentOptions,
  type WarmedAuthStrategy,
} from "@cipherstash/auth/start";

const federate = {
  workspaceCrn: "crn:r:w",
  getJwt: async () => "jwt",
};
// An options object typed as the whole options type may carry either onError.
const anyOptions: CsFederateCurrentOptions = federate;

const csAuth = createMiddleware({ type: "function" }).server(async ({ next }) => {
  const csAuth = await csFederateCurrent(federate);
  return next({ context: { csAuth } });
});

const csAuthOptional = createMiddleware({ type: "function" }).server(async ({ next }) => {
  const csAuth = await csFederateCurrent({ ...federate, onError: "null" });
  return next({ context: { csAuth } });
});

export const loadSecret = createServerFn({ method: "GET" })
  .middleware([csAuth])
  .handler(async ({ context }) => {
    const strategy: WarmedAuthStrategy = context.csAuth;
    const result = await strategy.getToken();
    return result.failure ? null : result.data.workspaceId;
  });

export const maybeSignedOut = createServerFn()
  .middleware([csAuthOptional])
  .handler(async ({ context }) => {
    // @ts-expect-error csAuth may be null under onError: "null"
    const strategy: WarmedAuthStrategy = context.csAuth;
    void strategy;
    return context.csAuth === null;
  });

export const startInstance = createStart(() => ({ functionMiddleware: [csAuthOptional] }));

// A default call is non-null; an onError chosen at runtime is accepted, and
// typed as possibly null.
export async function narrowing(isPublic: boolean) {
  const strict: WarmedAuthStrategy = await csFederateCurrent({ workspaceCrn: "crn:r:w", getJwt: () => "jwt" });
  const chosen = await csFederateCurrent({
    workspaceCrn: "crn:r:w",
    getJwt: () => "jwt",
    onError: isPublic ? "null" : "throw",
  });
  // @ts-expect-error a runtime-chosen onError may resolve null
  const notNull: WarmedAuthStrategy = chosen;
  const whole: WarmedAuthStrategy | null = await csFederateCurrent(anyOptions);
  void strict; void notNull; void whole;
}

// A cookie jar and the request/responseHeaders pair are alternatives: each
// call takes exactly one, and csFederateCurrent takes neither.
export function oneCookieSource(request: Request, responseHeaders: Headers, jar: CookieJar) {
  const common = { workspaceCrn: "crn:r:w", getJwt: () => "jwt" };
  const explicit: CsFederateOptions = { ...common, request, responseHeaders };
  cookieStore({ request, responseHeaders });
  cookieStore({ jar });
  void csFederate(explicit);
  void csFederate({ ...common, jar });
  // @ts-expect-error both sources
  cookieStore({ request, responseHeaders, jar });
  // @ts-expect-error half of the header pair, plus a jar
  cookieStore({ request, jar });
  // @ts-expect-error both sources
  void csFederate({ ...common, request, responseHeaders, jar });
  // @ts-expect-error csFederateCurrent reads the request Start is handling
  void csFederateCurrent({ ...common, request, responseHeaders });
  // @ts-expect-error nor through a csFederate options variable
  void csFederateCurrent(explicit);
  // @ts-expect-error csFederateCurrent passes Start's own jar
  void csFederateCurrent({ ...common, jar });
}

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
import { createMiddleware, createServerFn } from "@tanstack/react-start";
import { csFederateCurrent } from "@cipherstash/auth/start";

const csAuth = createMiddleware({ type: "function" }).server(async ({ next }) => {
  const csAuth = await csFederateCurrent({ workspaceCrn: "crn:r:w", getJwt: () => "jwt" });
  return next({ context: { csAuth } });
});
export const fn = createServerFn()
  .middleware([csAuth])
  .handler(async ({ context }) => {
    const s: string = context.csAuth;
    return s;
  });
`

/**
 * A scratch project whose `node_modules` links `@cipherstash/auth` to this
 * package and `@tanstack` to the package's own install, so the consumer
 * resolves both the way a real install does.
 */
function scratchProject(): string {
  const dir = scratchDir('cs-auth-start-tscheck-')
  mkdirSync(join(dir, 'node_modules', '@cipherstash'), { recursive: true })
  symlinkSync(packageDir, join(dir, 'node_modules', '@cipherstash', 'auth'))
  symlinkSync(
    join(packageDir, 'node_modules', '@tanstack'),
    join(dir, 'node_modules', '@tanstack'),
  )
  return dir
}

function typecheckConsumer(
  source: string,
  moduleResolution: 'Node16' | 'bundler',
) {
  const dir = scratchProject()
  writeFileSync(join(dir, 'consumer.mts'), source)
  return runTsc(dir, {
    compilerOptions: {
      target: 'ES2022',
      module: moduleResolution === 'Node16' ? 'Node16' : 'ESNext',
      moduleResolution,
      strict: true,
      esModuleInterop: true,
      // What a Start app sets: TanStack's own typings reference `react` and
      // `node:` modules whose `@types` this package does not install. This
      // package's declarations are checked with it off, below.
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

  it('the declaration files type-check on their own with skipLibCheck off', () => {
    // `skipLibCheck: true` above would also hide an error INSIDE a declaration
    // file — an unresolved import there degrades to `any` silently. These
    // files import nothing outside the package, so they must be clean with
    // every declaration checked.
    const dir = scratchProject()
    const { ok, output } = runTsc(dir, {
      compilerOptions: {
        target: 'ES2022',
        module: 'Node16',
        moduleResolution: 'Node16',
        strict: true,
        skipLibCheck: false,
        noEmit: true,
      },
      files: ['start.d.mts', 'next.d.ts', 'cookies.d.ts', 'warmed.d.ts'].map(
        (file) => `node_modules/@cipherstash/auth/${file}`,
      ),
    })
    expect(ok, `tsc reported errors:\n${output}`).toBe(true)
  })
})

describe('publish contract (npm pack)', () => {
  it('packs the /start entry and the shared warmed-strategy module', () => {
    // `start.mjs` imports `./warmed.mjs` and `start.d.mts` imports
    // `./warmed.d.ts`; a `files` allowlist that forgot either would publish an
    // entry that dangles on a missing file.
    expect(packedFiles()).toEqual(
      expect.arrayContaining([
        'start.mjs',
        'start.d.mts',
        'warmed.mjs',
        'warmed.d.ts',
      ]),
    )
  })
})
