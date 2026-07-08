import { afterEach, describe, expect, it, vi } from 'vitest'

// login.ts imports the native `@cipherstash/auth` binary. Replacing the module
// before load keeps it out of the fast unit suite (mirrors how region.test.ts
// mocks `@clack/prompts`) so the pure json-mode logic is testable in isolation.
const authMock = vi.hoisted(() => ({
  beginDeviceCodeFlow: vi.fn(),
  bindClientDevice: vi.fn(),
}))
vi.mock('@cipherstash/auth', () => ({ default: authMock }))
vi.mock('@clack/prompts', () => ({
  spinner: () => ({ start: vi.fn(), stop: vi.fn() }),
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
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
})
