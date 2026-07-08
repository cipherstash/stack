import { afterEach, describe, expect, it, vi } from 'vitest'

// login.ts imports the native `@cipherstash/auth` binary. Replacing the module
// before load keeps it out of the fast unit suite (mirrors how region.test.ts
// mocks `@clack/prompts`) so the pure json-mode logic is testable in isolation.
const authMock = vi.hoisted(() => ({
  beginDeviceCodeFlow: vi.fn(),
  bindClientDevice: vi.fn(),
}))
vi.mock('@cipherstash/auth', () => ({ default: authMock }))

// Hoisted so the interactive (non-json) path — spinner + `p.log.warn` — is
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

/** A device-code `pending` handle with overridable fields. */
function makePending(over: Record<string, unknown> = {}) {
  return {
    userCode: 'ABCD-1234',
    verificationUri: 'https://cs.test/device',
    verificationUriComplete: 'https://cs.test/device?code=ABCD-1234',
    expiresIn: 900,
    openInBrowser: vi.fn(() => true),
    pollForToken: vi.fn(async () => ({ expiresAt: 1_700_000_000 })),
    ...over,
  }
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
    const pending = makePending()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(pending)
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
    const pending = makePending()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(pending)
    captureJsonLines()

    // No `open` passed — json mode must default to not opening (the human,
    // not the agent host, opens the URL).
    await login('us-east-1.aws', undefined, { json: true })

    expect(pending.openInBrowser).not.toHaveBeenCalled()
  })

  it('maps a begin failure to a JSON error event (code from AuthError) and exits 1', async () => {
    authMock.beginDeviceCodeFlow.mockRejectedValueOnce(
      Object.assign(new Error('bad client'), { code: 'INVALID_CLIENT' }),
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

  it('falls back to begin_failed when the error has no code', async () => {
    authMock.beginDeviceCodeFlow.mockRejectedValueOnce(
      new Error('network down'),
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

  it('maps a poll failure to a poll_failed JSON error and exits 1', async () => {
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(
      makePending({
        pollForToken: vi.fn(async () => {
          throw new Error('timed out')
        }),
      }),
    )
    const exit = spyExit()
    const out = captureJsonLines()

    await expect(
      login('us-east-1.aws', undefined, { json: true, open: false }),
    ).rejects.toThrow('process.exit')

    expect(exit).toHaveBeenCalledWith(1)
    // First line is the trigger event; the error follows on the next line.
    const lines = out.lines()
    expect(lines[0]).toMatchObject({ status: 'authorization_required' })
    expect(lines[1]).toMatchObject({ status: 'error', code: 'poll_failed' })
  })
})

describe('bindDevice — json mode', () => {
  it('emits device_bound on success', async () => {
    authMock.bindClientDevice.mockResolvedValueOnce(undefined)
    const out = captureJsonLines()

    await bindDevice({ json: true })

    expect(out.lines()[0]).toEqual({ status: 'device_bound' })
  })

  it('emits a bind_failed error and exits 1 on failure', async () => {
    authMock.bindClientDevice.mockRejectedValueOnce(
      new Error('keyset unreachable'),
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

  it('carries the AuthError .code when the bind failure has one', async () => {
    // The code-present branch of `authErrorCode(error) ?? 'bind_failed'` — the
    // fallback above covers code-absent; this pins the pass-through.
    authMock.bindClientDevice.mockRejectedValueOnce(
      Object.assign(new Error('keyset locked'), { code: 'KEYSET_LOCKED' }),
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
    const pending = makePending()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(pending)

    // No `open` passed: interactive mode (json:false) defaults to opening.
    await login('us-east-1.aws', undefined, { json: false })

    expect(pending.openInBrowser).toHaveBeenCalledTimes(1)
    expect(clack.log.warn).not.toHaveBeenCalled()
  })

  it('does not open the browser when open: false on the interactive path', async () => {
    const pending = makePending()
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(pending)

    await login('us-east-1.aws', undefined, { json: false, open: false })

    expect(pending.openInBrowser).not.toHaveBeenCalled()
  })

  it('warns (interactive only) when the browser could not be opened', async () => {
    const pending = makePending({ openInBrowser: vi.fn(() => false) })
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(pending)

    await login('us-east-1.aws', undefined, { json: false })

    expect(pending.openInBrowser).toHaveBeenCalledTimes(1)
    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not open browser'),
    )
  })
})

describe('login — interactive (non-json) error propagation', () => {
  it('rethrows a begin failure and does NOT call process.exit', async () => {
    authMock.beginDeviceCodeFlow.mockRejectedValueOnce(new Error('begin boom'))
    const exit = spyExit()

    // Asserting the original message (not 'process.exit') proves the
    // interactive path propagated the error instead of exiting.
    await expect(
      login('us-east-1.aws', undefined, { json: false }),
    ).rejects.toThrow('begin boom')
    expect(exit).not.toHaveBeenCalled()
  })

  it('rethrows a poll failure and does NOT call process.exit', async () => {
    authMock.beginDeviceCodeFlow.mockResolvedValueOnce(
      makePending({
        pollForToken: vi.fn(async () => {
          throw new Error('poll boom')
        }),
      }),
    )
    const exit = spyExit()

    await expect(
      login('us-east-1.aws', undefined, { json: false, open: false }),
    ).rejects.toThrow('poll boom')
    expect(exit).not.toHaveBeenCalled()
  })
})
