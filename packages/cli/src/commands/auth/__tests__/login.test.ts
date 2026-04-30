import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  makeAuthError,
  makeDeviceCodeResult,
} from '../../../../tests/helpers/auth-mock.js'
import { messages } from '../../../messages.js'

// Hoisted stubs — `vi.mock` factories run before module imports, but we need
// the same fn instances inside the factory and the test bodies so tests can
// reconfigure behaviour per-case via mockResolvedValueOnce / mockRejectedValueOnce.
const stubs = vi.hoisted(() => ({
  beginDeviceCodeFlow: vi.fn(),
  bindClientDevice: vi.fn(),
}))

vi.mock('@cipherstash/auth', () => ({
  default: {
    beginDeviceCodeFlow: stubs.beginDeviceCodeFlow,
    bindClientDevice: stubs.bindClientDevice,
    // The login module destructures only the two functions above, but we
    // include the strategy classes so any side-importer doesn't blow up.
    AutoStrategy: { detect: vi.fn() },
    AccessKeyStrategy: { create: vi.fn() },
    OAuthStrategy: { fromProfile: vi.fn() },
  },
}))

const clack = vi.hoisted(() => ({
  select: vi.fn(),
  isCancel: vi.fn(),
  cancel: vi.fn(),
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), success: vi.fn() },
  spinnerStart: vi.fn(),
  spinnerStop: vi.fn(),
}))

vi.mock('@clack/prompts', () => ({
  select: clack.select,
  isCancel: clack.isCancel,
  cancel: clack.cancel,
  log: clack.log,
  spinner: () => ({ start: clack.spinnerStart, stop: clack.spinnerStop }),
}))

// Import after mocks are registered.
const { bindDevice, login, selectRegion } = await import('../login.js')

describe('selectRegion', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns the chosen region when not cancelled', async () => {
    clack.select.mockResolvedValueOnce('us-east-1.aws')
    clack.isCancel.mockReturnValueOnce(false)

    const result = await selectRegion()

    expect(result).toBe('us-east-1.aws')
    expect(clack.cancel).not.toHaveBeenCalled()
    // Sanity: select was called with the message handle, not a literal.
    expect(clack.select).toHaveBeenCalledWith(
      expect.objectContaining({ message: messages.auth.selectRegion }),
    )
  })

  it('cancels via clack and exits 0 when the prompt is cancelled', async () => {
    const exitSpy = vi
      .spyOn(process, 'exit')
      .mockImplementation((() => undefined) as never)
    const cancelSym = Symbol('clack:cancel')
    clack.select.mockResolvedValueOnce(cancelSym)
    clack.isCancel.mockReturnValueOnce(true)

    await selectRegion()

    expect(clack.cancel).toHaveBeenCalledWith(messages.auth.cancelled)
    expect(exitSpy).toHaveBeenCalledWith(0)
    exitSpy.mockRestore()
  })
})

describe('login', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('runs the full device-code sequence on the happy path', async () => {
    const dcr = makeDeviceCodeResult()
    stubs.beginDeviceCodeFlow.mockResolvedValueOnce(dcr)

    await login('us-east-1.aws', 'drizzle')

    expect(stubs.beginDeviceCodeFlow).toHaveBeenCalledWith(
      'us-east-1.aws',
      // Hardcoded 'cli' OAuth client id — anything else is INVALID_CLIENT.
      'cli',
    )
    expect(dcr.openInBrowser).toHaveBeenCalledTimes(1)
    expect(clack.spinnerStart).toHaveBeenCalledTimes(1)
    expect(dcr.pollForToken).toHaveBeenCalledTimes(1)
    expect(clack.spinnerStop).toHaveBeenCalledWith('Authenticated!')
  })

  it('warns when the browser cannot be opened', async () => {
    const dcr = makeDeviceCodeResult({ openInBrowser: vi.fn(() => false) })
    stubs.beginDeviceCodeFlow.mockResolvedValueOnce(dcr)

    await login('eu-west-1.aws', undefined)

    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('Could not open browser'),
    )
  })

  it.each(['EXPIRED_TOKEN', 'ACCESS_DENIED', 'REQUEST_ERROR', 'SERVER_ERROR'])(
    'propagates AuthError(%s) from pollForToken without stopping the spinner',
    async (code) => {
      const dcr = makeDeviceCodeResult({
        // biome-ignore lint/suspicious/noExplicitAny: cast keeps the narrow AuthErrorCode union accessible to it.each
        pollForToken: vi.fn().mockRejectedValueOnce(makeAuthError(code as any)),
      })
      stubs.beginDeviceCodeFlow.mockResolvedValueOnce(dcr)

      await expect(login('us-east-1.aws', undefined)).rejects.toMatchObject({
        code,
      })
      expect(clack.spinnerStart).toHaveBeenCalledTimes(1)
      expect(clack.spinnerStop).not.toHaveBeenCalled()
    },
  )
})

describe('bindDevice', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('stops the spinner with success when bindClientDevice resolves', async () => {
    stubs.bindClientDevice.mockResolvedValueOnce(undefined)

    await bindDevice()

    expect(stubs.bindClientDevice).toHaveBeenCalledTimes(1)
    expect(clack.spinnerStop).toHaveBeenCalledWith(
      expect.stringContaining('bound'),
    )
    expect(clack.log.error).not.toHaveBeenCalled()
  })

  it('logs the error and exits 1 on bindClientDevice failure', async () => {
    const exitSpy = vi
      .spyOn(process, 'exit')
      .mockImplementation((() => undefined) as never)
    stubs.bindClientDevice.mockRejectedValueOnce(
      makeAuthError('ACCESS_DENIED', 'no permission'),
    )

    await bindDevice()

    expect(clack.spinnerStop).toHaveBeenCalledWith(
      expect.stringContaining('Failed to bind'),
    )
    expect(clack.log.error).toHaveBeenCalledWith('no permission')
    expect(exitSpy).toHaveBeenCalledWith(1)
  })
})
