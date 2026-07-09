import { afterEach, describe, expect, it, vi } from 'vitest'

// login.ts imports the native `@cipherstash/auth` binary. Replacing the module
// before load keeps it out of the fast unit suite (mirrors how region.test.ts
// mocks `@clack/prompts`) so the pure json-mode logic is testable in isolation.
//
// As of `@cipherstash/auth` 0.41 the device-code flow returns
// `Result<T, AuthFailure>` (`{ data }` on success, `{ failure: { type, error } }`
// on error) instead of throwing — the mocks below mirror that shape.
const authMock = vi.hoisted(() => ({
  beginDeviceCodeFlow: vi.fn(),
  bindClientDevice: vi.fn(),
}))
vi.mock('@cipherstash/auth', () => ({ default: authMock }))

// Hoisted so the interactive (non-json) path — spinner + `p.log.*` — is
// observable; a single spinner instance is returned from every `p.spinner()`.
const clack = vi.hoisted(() => {
  const spinnerInstance = { start: vi.fn(), stop: vi.fn() }
  return {
    spinnerInstance,
    spinner: vi.fn(() => spinnerInstance),
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
  }
})
vi.mock('@clack/prompts', () => ({
  spinner: clack.spinner,
  log: clack.log,
}))

const { login, bindDevice } = await import('../login.js')

/** A device-code `flow` handle (the `.data` of a successful `beginDeviceCodeFlow`). */
function makeFlow(over: Record<string, unknown> = {}) {
  return {
    userCode: 'ABCD-1234',
    verificationUri: 'https://cs.test/device',
    verificationUriComplete: 'https://cs.test/device?code=ABCD-1234',
    expiresIn: 900,
    // 0.41: these return Results too.
    openInBrowser: vi.fn(() => ({ data: true })),
    pollForToken: vi.fn(async () => ({ data: { expiresAt: 1_700_000_000 } })),
    ...over,
  }
}

/** An AuthFailure Result envelope for the failure arm. */
function failure(type: string | undefined, message: string) {
  return { failure: { type, error: new Error(message) } }
}

/** Capture NDJSON lines written to stdout as parsed objects. */
function captureJsonLines(): { lines: () => Record<string, unknown>[] } {
  const raw: string[] = []
  vi.spyOn(console, 'log').mockImplementation((l) => {
    raw.push(l as string)
  })
  return { lines: () => raw.map((l) => JSON.parse(l)) }
}

/** Spy process.exit so the code-under-test unwinds via a throw we can assert. */
function spyExit() {
  return vi.spyOn(process, 'exit').mockImplementation((() => {
    throw new Error('process.exit')
  }) as never)
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('login — json mode', () => {
  it('emits authorization_required then authorized', async () => {
    const flow = makeFlow()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce({ data: flow })
    const out = captureJsonLines()

    await login('us-east-1.aws', undefined, { json: true, open: false })

    const [first, second] = out.lines()
    expect(first).toMatchObject({
      status: 'authorization_required',
      userCode: 'ABCD-1234',
      verificationUri: 'https://cs.test/device',
      verificationUriComplete: 'https://cs.test/device?code=ABCD-1234',
      expiresIn: 900,
    })
    expect(second).toMatchObject({
      status: 'authorized',
      expiresAt: 1_700_000_000,
      expiresAtIso: new Date(1_700_000_000 * 1000).toISOString(),
    })
  })

  it('does not auto-open a browser in json mode by default', async () => {
    const flow = makeFlow()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce({ data: flow })
    captureJsonLines()

    // No `open` passed — json mode must default to not opening (the human,
    // not the agent host, opens the URL).
    await login('us-east-1.aws', undefined, { json: true })

    expect(flow.openInBrowser).not.toHaveBeenCalled()
  })

  it('maps a begin failure to a JSON error event (code from AuthFailure.type) and exits 1', async () => {
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(
      failure('INVALID_CLIENT', 'bad client'),
    )
    const exit = spyExit()
    const out = captureJsonLines()

    await expect(
      login('us-east-1.aws', undefined, { json: true }),
    ).rejects.toThrow('process.exit')

    expect(exit).toHaveBeenCalledWith(1)
    expect(out.lines()[0]).toMatchObject({
      status: 'error',
      code: 'INVALID_CLIENT',
      message: 'bad client',
    })
  })

  it('falls back to begin_failed when the failure carries no type', async () => {
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(
      failure(undefined, 'network down'),
    )
    spyExit()
    const out = captureJsonLines()

    await expect(
      login('us-east-1.aws', undefined, { json: true }),
    ).rejects.toThrow('process.exit')

    expect(out.lines()[0]).toMatchObject({
      status: 'error',
      code: 'begin_failed',
      message: 'network down',
    })
  })

  it('maps a poll failure to a JSON error (failure type) and exits 1', async () => {
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce({
      data: makeFlow({
        pollForToken: vi.fn(async () => failure('EXPIRED_TOKEN', 'timed out')),
      }),
    })
    const exit = spyExit()
    const out = captureJsonLines()

    await expect(
      login('us-east-1.aws', undefined, { json: true, open: false }),
    ).rejects.toThrow('process.exit')

    expect(exit).toHaveBeenCalledWith(1)
    // First line is the trigger event; the error follows on the next line.
    const lines = out.lines()
    expect(lines[0]).toMatchObject({ status: 'authorization_required' })
    expect(lines[1]).toMatchObject({ status: 'error', code: 'EXPIRED_TOKEN' })
  })
})

describe('bindDevice — json mode', () => {
  it('emits device_bound on success', async () => {
    authMock.bindClientDevice.mockResolvedValueOnce({ data: undefined })
    const out = captureJsonLines()

    await bindDevice({ json: true })

    expect(out.lines()[0]).toEqual({ status: 'device_bound' })
  })

  it('emits a bind_failed error and exits 1 when the failure carries no type', async () => {
    authMock.bindClientDevice.mockResolvedValueOnce(
      failure(undefined, 'keyset unreachable'),
    )
    const exit = spyExit()
    const out = captureJsonLines()

    await expect(bindDevice({ json: true })).rejects.toThrow('process.exit')

    expect(exit).toHaveBeenCalledWith(1)
    expect(out.lines()[0]).toMatchObject({
      status: 'error',
      code: 'bind_failed',
      message: 'keyset unreachable',
    })
  })

  it('carries the AuthFailure type when the bind failure has one', async () => {
    authMock.bindClientDevice.mockResolvedValueOnce(
      failure('KEYSET_LOCKED', 'keyset locked'),
    )
    const exit = spyExit()
    const out = captureJsonLines()

    await expect(bindDevice({ json: true })).rejects.toThrow('process.exit')

    expect(exit).toHaveBeenCalledWith(1)
    expect(out.lines()[0]).toMatchObject({
      status: 'error',
      code: 'KEYSET_LOCKED',
      message: 'keyset locked',
    })
  })
})

describe('login — interactive (non-json) browser open', () => {
  it('opens the browser exactly once on the interactive path', async () => {
    const flow = makeFlow()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce({ data: flow })

    // No `open` passed: interactive mode (json:false) defaults to opening.
    await login('us-east-1.aws', undefined, { json: false })

    expect(flow.openInBrowser).toHaveBeenCalledTimes(1)
    expect(clack.log.warn).not.toHaveBeenCalled()
  })

  it('does not open the browser when open: false on the interactive path', async () => {
    const flow = makeFlow()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce({ data: flow })

    await login('us-east-1.aws', undefined, { json: false, open: false })

    expect(flow.openInBrowser).not.toHaveBeenCalled()
  })

  it('warns (interactive only) when the browser could not be opened', async () => {
    // openInBrowser resolves `{ data: false }` — the "couldn't open" Result.
    const flow = makeFlow({ openInBrowser: vi.fn(() => ({ data: false })) })
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce({ data: flow })

    await login('us-east-1.aws', undefined, { json: false })

    expect(flow.openInBrowser).toHaveBeenCalledTimes(1)
    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not open browser'),
    )
  })
})

describe('login — interactive (non-json) failure handling', () => {
  it('surfaces a begin failure via p.log.error and exits 1 (no throw-through)', async () => {
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(
      failure('INVALID_CLIENT', 'begin boom'),
    )
    const exit = spyExit()

    await expect(
      login('us-east-1.aws', undefined, { json: false }),
    ).rejects.toThrow('process.exit')

    expect(exit).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith('begin boom')
  })

  it('surfaces a poll failure via p.log.error and exits 1', async () => {
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce({
      data: makeFlow({
        pollForToken: vi.fn(async () => failure('EXPIRED_TOKEN', 'poll boom')),
      }),
    })
    const exit = spyExit()

    await expect(
      login('us-east-1.aws', undefined, { json: false, open: false }),
    ).rejects.toThrow('process.exit')

    expect(exit).toHaveBeenCalledWith(1)
    expect(clack.log.error).toHaveBeenCalledWith('poll boom')
  })
})
