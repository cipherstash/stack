import * as p from '@clack/prompts'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'
import { resolveProxyChoiceStep } from '../resolve-proxy-choice.js'

vi.mock('@clack/prompts', () => ({
  select: vi.fn(),
  isCancel: vi.fn(() => false),
  log: { info: vi.fn(), success: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

const provider = {} as InitProvider
const baseState = {} as InitState

const originalStdinIsTTY = process.stdin.isTTY
const originalStdoutIsTTY = process.stdout.isTTY

/**
 * Force BOTH streams. A CI runner that allocates a TTY has stdin *and* stdout
 * as TTYs — that is the configuration this gate used to hang in, and setting
 * stdin alone would let the old `process.stdout.isTTY` gate pass these tests
 * for the wrong reason (vitest's own stdout is not a TTY).
 */
function setTty(value: boolean) {
  Object.defineProperty(process.stdin, 'isTTY', { value, configurable: true })
  Object.defineProperty(process.stdout, 'isTTY', { value, configurable: true })
}

function restoreTty() {
  Object.defineProperty(process.stdin, 'isTTY', {
    value: originalStdinIsTTY,
    configurable: true,
  })
  Object.defineProperty(process.stdout, 'isTTY', {
    value: originalStdoutIsTTY,
    configurable: true,
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  restoreTty()
  vi.unstubAllEnvs()
})

describe('resolveProxyChoiceStep — flag short-circuit', () => {
  it('returns state untouched when --proxy/--no-proxy already set it', async () => {
    setTty(true)
    vi.stubEnv('CI', '')

    const state = { ...baseState, usesProxy: true }
    await expect(resolveProxyChoiceStep.run(state, provider)).resolves.toEqual(
      state,
    )
    expect(vi.mocked(p.select)).not.toHaveBeenCalled()
  })

  it('returns state untouched when --no-proxy set usesProxy to false', async () => {
    // The guard is `state.usesProxy !== undefined`; `false` is the value that
    // distinguishes it from a truthiness check. Rewriting it as
    // `if (state.usesProxy)` would silently re-prompt for --no-proxy (and log
    // the misleading "No --proxy flag set" notice non-interactively).
    setTty(true)
    vi.stubEnv('CI', '')

    const state = { ...baseState, usesProxy: false }
    await expect(resolveProxyChoiceStep.run(state, provider)).resolves.toEqual(
      state,
    )
    expect(vi.mocked(p.select)).not.toHaveBeenCalled()
    // An explicit --no-proxy is not "no flag set" — don't log the default notice.
    expect(vi.mocked(p.log.info)).not.toHaveBeenCalled()
  })
})

describe('resolveProxyChoiceStep — CI detection with a TTY attached', () => {
  // Regression: this gate was `process.stdout.isTTY`, which consulted CI not
  // at all. On a CI runner with an allocated TTY the clack `select` rendered
  // and blocked on /dev/tty forever — a hang, not an error. `isInteractive()`
  // gates on stdin and treats CI=1/TRUE/true alike.
  beforeEach(() => {
    setTty(true)
  })

  for (const ciValue of ['1', 'TRUE', 'true']) {
    it(`defaults to SDK-only under CI=${ciValue} without prompting`, async () => {
      vi.stubEnv('CI', ciValue)

      const result = await resolveProxyChoiceStep.run(baseState, provider)

      // Non-interactive proceeds with the safe default rather than failing:
      // SDK-only is what the flagless interactive prompt defaults to anyway.
      expect(vi.mocked(p.select)).not.toHaveBeenCalled()
      expect(result.usesProxy).toBe(false)
      expect(vi.mocked(p.log.info)).toHaveBeenCalledWith(
        expect.stringContaining('defaulting to SDK-only mode'),
      )
    })
  }

  it('prompts when CI is unset and stdin is a TTY', async () => {
    vi.stubEnv('CI', '')
    vi.mocked(p.select).mockResolvedValueOnce(true)

    const result = await resolveProxyChoiceStep.run(baseState, provider)

    expect(vi.mocked(p.select)).toHaveBeenCalledTimes(1)
    expect(result.usesProxy).toBe(true)
  })

  it('falls back to SDK-only when the interactive prompt is cancelled', async () => {
    vi.stubEnv('CI', '')
    vi.mocked(p.select).mockResolvedValueOnce(Symbol('cancel'))
    vi.mocked(p.isCancel).mockReturnValueOnce(true)

    const result = await resolveProxyChoiceStep.run(baseState, provider)

    expect(result.usesProxy).toBe(false)
  })
})

describe('resolveProxyChoiceStep — no TTY', () => {
  it('defaults to SDK-only when stdin is not a TTY, CI unset', async () => {
    setTty(false)
    vi.stubEnv('CI', '')

    const result = await resolveProxyChoiceStep.run(baseState, provider)

    expect(vi.mocked(p.select)).not.toHaveBeenCalled()
    expect(result.usesProxy).toBe(false)
  })

  it('does not prompt when stdin is piped even though stdout is a TTY', async () => {
    // setTty() can't express this — it moves both streams together. The fix
    // gates on stdin, so a redirected stdin (`stash init < /dev/null` from a
    // terminal) must not reach the prompt even while stdout is still a TTY.
    // This is the case that verifies the changeset's "wrong stream" claim;
    // only the CI axis distinguishes old from new anywhere else.
    Object.defineProperty(process.stdin, 'isTTY', {
      value: false,
      configurable: true,
    })
    Object.defineProperty(process.stdout, 'isTTY', {
      value: true,
      configurable: true,
    })
    vi.stubEnv('CI', '')

    const result = await resolveProxyChoiceStep.run(baseState, provider)

    expect(vi.mocked(p.select)).not.toHaveBeenCalled()
    expect(result.usesProxy).toBe(false)
  })
})
