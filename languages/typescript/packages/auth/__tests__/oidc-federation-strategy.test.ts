import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MockCtsServer } from './helpers/mock-cts-server'

const { OidcFederationStrategy } =
  require('../index.js') as typeof import('../index')

const WORKSPACE_ID = 'ZVATKW3VHMFG27DY'
const WORKSPACE_CRN = `crn:ap-southeast-2.aws:${WORKSPACE_ID}`

let server: MockCtsServer
let savedHost: string | undefined

beforeEach(async () => {
  server = await MockCtsServer.start()
  // OidcFederationStrategy reads the CTS base URL from CS_CTS_HOST at runtime,
  // so set it before constructing the strategy.
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

/** A `getJwt` callback that counts invocations and returns a fixed JWT. */
function countingJwt() {
  let calls = 0
  return {
    calls: () => calls,
    getJwt: () => {
      calls += 1
      return Promise.resolve('header.payload.signature')
    },
  }
}

/** An in-memory `{ load, save }` token store dealing in JSON strings. */
function memStore() {
  let saved: string | null = null
  return {
    saved: () => saved,
    load: () => Promise.resolve(saved),
    save: (json: string) => {
      saved = json
      return Promise.resolve()
    },
  }
}

/** Unwrap a `create` Result, failing the test if it returned a failure. */
function mustCreate(
  ...args: Parameters<typeof OidcFederationStrategy.create>
): InstanceType<typeof OidcFederationStrategy> {
  const cr = OidcFederationStrategy.create(...args)
  if (cr.failure) {
    expect.unreachable(`create failed: ${cr.failure.type}`)
  }
  return cr.data
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

describe('OidcFederationStrategy (TypeScript / vitest)', () => {
  it('federates a third-party JWT into a CTS service token', async () => {
    server.mockAuthorizeEndpoint()
    const jwt = countingJwt()
    const strategy = mustCreate(WORKSPACE_CRN, jwt.getJwt)

    const r = await strategy.getToken()
    if (r.failure) {
      expect.unreachable(`getToken failed: ${r.failure.type}`)
    }
    const result = r.data

    expect(result.token).not.toBe('')
    expect(result.workspaceId).toBe(WORKSPACE_ID)
    expect(jwt.calls()).toBe(1)
  })

  it('surfaces WORKSPACE_MISMATCH with the expected/actual payload', async () => {
    // The federated token carries a different workspace than the strategy's CRN,
    // so workspace verification fails. This is the flagship structured-payload
    // failure — it exercises the `...payload` spread end to end (the named
    // help/url destructure doesn't), so it guards `failure.expected`/`.actual`
    // against a serde key rename or a spread regression at the JS boundary.
    const MISMATCHED_WORKSPACE = 'AAAAAAAAAAAAAAAA'
    server.mockAuthorizeEndpointWithWorkspace(MISMATCHED_WORKSPACE)
    const strategy = mustCreate(WORKSPACE_CRN, countingJwt().getJwt)

    const r = await strategy.getToken()
    if (!r.failure) {
      expect.unreachable('expected a WORKSPACE_MISMATCH failure')
    }
    const { failure } = r
    if (failure.type !== 'WORKSPACE_MISMATCH') {
      expect.unreachable(`expected WORKSPACE_MISMATCH, got ${failure.type}`)
    }
    expect(failure.expected).toBe(WORKSPACE_ID)
    expect(failure.actual).toBe(MISMATCHED_WORKSPACE)
    expect(failure.error).toBeInstanceOf(Error)
  })

  it('re-federates after the cached token expires', async () => {
    // expiry 0 → the federated token is immediately expired, so the second
    // getToken() must re-federate rather than serve a cached token.
    server.mockAuthorizeEndpoint(0)
    server.mockAuthorizeEndpoint(0)
    const jwt = countingJwt()
    const strategy = mustCreate(WORKSPACE_CRN, jwt.getJwt)

    await strategy.getToken()
    await strategy.getToken()

    expect(jwt.calls()).toBe(2)
  })

  it('surfaces a getJwt rejection as a failure with .type', async () => {
    server.mockAuthorizeEndpoint()
    const strategy = mustCreate(WORKSPACE_CRN, () =>
      Promise.reject(new Error('provider unavailable')),
    )

    const r = await strategy.getToken()
    expect(r.failure?.type).toBe('SERVER_ERROR')
  })

  it('honours an explicit baseUrl override over CS_CTS_HOST', async () => {
    // CS_CTS_HOST (set in beforeEach) points at `server`, which here 500s on
    // federation. A second server is the override target and succeeds. If the
    // napi `baseUrl` arg is threaded through `maybe_base_url`, federation hits
    // the override and resolves; if the override were dropped, it would hit
    // CS_CTS_HOST's 500 and reject. This proves the precedence guarantee
    // motivating CIP-3246 survives the napi parameter threading — the Rust core
    // proves the ordering, this proves the binding preserves it.
    server.mockAuthorizeEndpointError()
    const override = await MockCtsServer.start()
    try {
      override.mockAuthorizeEndpoint()
      const strategy = mustCreate(
        WORKSPACE_CRN,
        () => Promise.resolve('header.payload.signature'),
        override.baseUrl,
      )

      const r = await strategy.getToken()
      if (r.failure) {
        expect.unreachable(`getToken failed: ${r.failure.type}`)
      }

      expect(r.data.workspaceId).toBe(WORKSPACE_ID)
    } finally {
      await override.close()
    }
  })

  it('honours a baseUrl override over CS_CTS_HOST for createWithStore', async () => {
    // The store-variant twin of the precedence test: `baseUrl` is the 5th
    // positional arg here (vs the 3rd on `create`), threaded through a separate
    // wrapper path in index.js. CS_CTS_HOST's `server` 500s; the override
    // server succeeds. getToken resolving (and the token landing in the store)
    // proves the 5th-positional override is threaded, not dropped or
    // mis-positioned.
    server.mockAuthorizeEndpointError()
    const override = await MockCtsServer.start()
    try {
      override.mockAuthorizeEndpoint()
      const store = memStore()
      const strategy = mustCreateWithStore(
        WORKSPACE_CRN,
        () => Promise.resolve('header.payload.signature'),
        store.load,
        store.save,
        override.baseUrl,
      )

      const r = await strategy.getToken()
      if (r.failure) {
        expect.unreachable(`getToken failed: ${r.failure.type}`)
      }

      expect(r.data.workspaceId).toBe(WORKSPACE_ID)
      expect(store.saved()).not.toBeNull()
    } finally {
      await override.close()
    }
  })

  it('rejects a malformed baseUrl with INVALID_URL', () => {
    // The napi twin of the wasm `..._rejects_invalid_base_url` test: a
    // non-empty, unparseable override must surface through the factory as a
    // coded INVALID_URL failure (via `maybe_base_url(...)? → to_napi_error`), not
    // a silent fallback or an un-coded throw.
    const cr = OidcFederationStrategy.create(
      WORKSPACE_CRN,
      () => Promise.resolve('h.p.s'),
      'not a url',
    )
    expect(cr.failure?.type).toBe('INVALID_URL')
  })

  it('treats an empty baseUrl as absent (falls back to CS_CTS_HOST)', async () => {
    // An empty-string override must be a no-op, not an INVALID_URL — so
    // federation still resolves against CS_CTS_HOST's mock.
    server.mockAuthorizeEndpoint()
    const strategy = mustCreate(
      WORKSPACE_CRN,
      () => Promise.resolve('header.payload.signature'),
      '',
    )

    const r = await strategy.getToken()
    if (r.failure) {
      expect.unreachable(`getToken failed: ${r.failure.type}`)
    }

    expect(r.data.workspaceId).toBe(WORKSPACE_ID)
  })

  it('rejects an invalid workspace CRN with .type', () => {
    const cr = OidcFederationStrategy.create('not-a-crn', () =>
      Promise.resolve('h.p.s'),
    )
    expect(cr.failure?.type).toBe('INVALID_CRN')
  })

  it('attaches diagnostic help to an INVALID_CRN failure', () => {
    // INVALID_CRN carries `#[diagnostic(help(...))]`, so its envelope includes
    // `help` — pins the `help !== undefined` branch of `toFailure` in index.js
    // with a content assertion, not just presence: the text must survive the
    // __CS_FAIL__ envelope round-trip intact.
    const cr = OidcFederationStrategy.create('not-a-crn', () =>
      Promise.resolve('h.p.s'),
    )
    expect(cr.failure?.type).toBe('INVALID_CRN')
    expect(typeof cr.failure?.help).toBe('string')
    expect(cr.failure?.help).toMatch(/crn:<region>:<workspace-id>/)
    // The same help is mirrored onto the live Error for loggers that only
    // see the error object.
    expect((cr.failure?.error as Error & { help?: string }).help).toBe(
      cr.failure?.help,
    )
  })

  it('rejects a CRN whose workspace segment is malformed with .type', () => {
    // "not-a-crn" above fails at the `crn:` prefix; this is the distinct path
    // where the prefix/region parse but the workspace segment fails validation
    // — what the old INVALID_WORKSPACE_ID case covered before the CRN switch.
    const cr = OidcFederationStrategy.create(
      'crn:ap-southeast-2.aws:not-a-valid-workspace',
      () => Promise.resolve('h.p.s'),
    )
    expect(cr.failure?.type).toBe('INVALID_CRN')
  })

  it('persists the federated token to the store', async () => {
    server.mockAuthorizeEndpoint()
    const store = memStore()
    const jwt = countingJwt()
    const strategy = mustCreateWithStore(
      WORKSPACE_CRN,
      jwt.getJwt,
      store.load,
      store.save,
    )

    await strategy.getToken()

    expect(store.saved()).not.toBeNull()
    expect(jwt.calls()).toBe(1)
  })

  it('loads a cached token from the store without re-federating', async () => {
    // First strategy federates and populates the shared store.
    server.mockAuthorizeEndpoint()
    const store = memStore()
    const first = mustCreateWithStore(
      WORKSPACE_CRN,
      () => Promise.resolve('h.p.s'),
      store.load,
      store.save,
    )
    await first.getToken()
    expect(store.saved()).not.toBeNull()

    // Second strategy shares the store. Federation would fail (500) and getJwt
    // would throw — proving the token came from the store, not the network.
    server.clearMocks()
    server.mockAuthorizeEndpointError()
    const second = mustCreateWithStore(
      WORKSPACE_CRN,
      () => Promise.reject(new Error('getJwt must not be called')),
      store.load,
      store.save,
    )

    const r = await second.getToken()
    if (r.failure) {
      expect.unreachable(`getToken failed: ${r.failure.type}`)
    }
    expect(r.data.workspaceId).toBe(WORKSPACE_ID)
  })

  it('re-federates when the stored token JSON is malformed', async () => {
    // A corrupt cookie/store value must be treated as a cache miss (the
    // `serde_json::from_str(..).ok()` → None branch), not panic — so federation
    // runs fresh. A version that `unwrap()`ed the parse would fail this.
    server.mockAuthorizeEndpoint()
    const jwt = countingJwt()
    const strategy = mustCreateWithStore(
      WORKSPACE_CRN,
      jwt.getJwt,
      () => Promise.resolve('}{ not json'),
      (_json: string) => Promise.resolve(),
    )

    await strategy.getToken()

    // Garbage cache discarded → exactly one fresh federation.
    expect(jwt.calls()).toBe(1)
  })

  it('surfaces a non-string getJwt result as a failure with .type', async () => {
    // Mirrors the wasm `js_oidc_provider_errors_on_non_string_result` test:
    // a `Promise<number>` fails napi's `Promise<String>` coercion and must
    // surface as a clean SERVER_ERROR failure, not a panic or hung promise.
    server.mockAuthorizeEndpoint()
    const strategy = mustCreate(WORKSPACE_CRN, () =>
      Promise.resolve(42 as unknown as string),
    )

    const r = await strategy.getToken()
    expect(r.failure?.type).toBe('SERVER_ERROR')
  })

  it('surfaces a federation server error with .type', async () => {
    // Negative twin of the happy path: a real federation request reaching
    // /api/authorise and getting a 500 must surface a failure with a `.type`,
    // not resolve or throw an un-coded error.
    server.mockAuthorizeEndpointError()
    const strategy = mustCreate(WORKSPACE_CRN, () =>
      Promise.resolve('header.payload.signature'),
    )

    const r = await strategy.getToken()
    expect(r.failure).toBeTruthy()
    expect(r.failure?.type).toBeTruthy()
  })
})
