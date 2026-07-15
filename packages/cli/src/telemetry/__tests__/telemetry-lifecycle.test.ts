import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CI_ENV_VARS } from '../../config/tty.js'
import type { TelemetryState } from '../state.js'

// Controllable doubles for posthog-node and the on-disk state, wired via
// vi.hoisted so the (hoisted) vi.mock factories can close over them.
const h = vi.hoisted(() => ({
  capture: vi.fn(),
  shutdown: vi.fn(async () => {}),
  PostHog: vi.fn(),
  writeState: vi.fn(),
  state: { value: undefined as TelemetryState | undefined },
}))

vi.mock('posthog-node', () => ({ PostHog: h.PostHog }))
vi.mock('../state.js', () => ({
  readState: () => h.state.value,
  writeState: (s: TelemetryState) => {
    h.writeState(s)
    h.state.value = s
    return s
  },
}))

/** Re-import the module fresh so its lazily-initialised caches reset per test. */
async function load() {
  vi.resetModules()
  return import('../index.js')
}

const ENABLED: TelemetryState = {
  anonymousId: 'anon-x',
  telemetryDisabled: false,
  noticeShownAt: '2026-01-01T00:00:00.000Z',
}

describe('telemetry lifecycle (emitter + flush)', () => {
  beforeEach(() => {
    h.capture.mockReset()
    h.shutdown.mockReset().mockResolvedValue(undefined)
    h.PostHog.mockReset().mockImplementation(() => ({
      capture: h.capture,
      shutdown: h.shutdown,
    }))
    h.writeState.mockReset()
    h.state.value = { ...ENABLED }
    // Enabled by default; neutralize every gate so status is { enabled: true }.
    vi.stubEnv('STASH_POSTHOG_KEY', 'phc_test_key')
    for (const name of [
      'DO_NOT_TRACK',
      'STASH_TELEMETRY_DISABLED',
      ...CI_ENV_VARS,
    ]) {
      vi.stubEnv(name, '')
    }
  })
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.useRealTimers()
  })

  it('trackCommand builds no client and sends nothing when disabled', async () => {
    vi.stubEnv('STASH_POSTHOG_KEY', '') // dormant
    const t = await load()
    t.trackCommand({ command: 'init', success: true, durationMs: 1 })
    await t.shutdownTelemetry()
    expect(h.PostHog).not.toHaveBeenCalled()
    expect(h.capture).not.toHaveBeenCalled()
  })

  it('trackCommand is a no-op on the first run (freebie)', async () => {
    h.state.value = { anonymousId: 'a', telemetryDisabled: false } // no noticeShownAt
    const t = await load()
    t.trackCommand({ command: 'init', success: true, durationMs: 1 })
    await t.shutdownTelemetry()
    expect(h.PostHog).not.toHaveBeenCalled()
  })

  it('captures one anonymous event and flushes on shutdown', async () => {
    const t = await load()
    t.initTelemetry('9.9.9')
    t.trackCommand({
      command: 'eql',
      subcommand: 'install',
      success: true,
      durationMs: 5,
    })
    await t.shutdownTelemetry()
    expect(h.PostHog).toHaveBeenCalledTimes(1)
    expect(h.capture).toHaveBeenCalledTimes(1)
    const arg = h.capture.mock.calls[0][0]
    expect(arg.distinctId).toBe('anon-x')
    expect(arg.event).toBe('command_invoked')
    expect(arg.properties.command).toBe('eql')
    expect(arg.properties.cliVersion).toBe('9.9.9')
    expect(arg.properties.$process_person_profile).toBe(false)
    expect(h.shutdown).toHaveBeenCalledTimes(1)
  })

  it('swallows a throwing capture and still shuts down cleanly', async () => {
    h.capture.mockImplementation(() => {
      throw new Error('boom')
    })
    const t = await load()
    t.trackCommand({ command: 'init', success: true, durationMs: 1 })
    await expect(t.shutdownTelemetry()).resolves.toBeUndefined()
  })

  it('shutdownTelemetry is a safe no-op when nothing was captured, even twice', async () => {
    const t = await load()
    await expect(t.shutdownTelemetry()).resolves.toBeUndefined()
    await expect(t.shutdownTelemetry()).resolves.toBeUndefined()
    expect(h.shutdown).not.toHaveBeenCalled()
  })

  /** Save/restore stderr.isTTY faithfully: when the property wasn't an own
   * property (vitest pipes stderr, so isTTY is undefined and absent), restore
   * ABSENCE — a defineProperty with `value: undefined` would create a read-only
   * own property that breaks later `isTTY = …` assignments in sibling tests. */
  function withStderrTty(isTTY: boolean, run: () => void | Promise<void>) {
    const original = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY')
    Object.defineProperty(process.stderr, 'isTTY', {
      value: isTTY,
      configurable: true,
    })
    const restore = () => {
      if (original) Object.defineProperty(process.stderr, 'isTTY', original)
      else delete (process.stderr as { isTTY?: boolean }).isTTY
    }
    const result = run()
    if (result instanceof Promise) return result.finally(restore)
    restore()
    return result
  }

  it('shows + persists the first-run notice even when stderr is NOT a TTY, and keeps noticeShownAt across setTelemetryDisabled', async () => {
    h.state.value = { anonymousId: 'a', telemetryDisabled: false } // firstRun
    const write = vi.spyOn(process.stderr, 'write').mockReturnValue(true)
    try {
      await withStderrTty(false, async () => {
        const t = await load()
        t.maybeShowFirstRunNotice('npx stash')
        expect(write).toHaveBeenCalledTimes(1)
        expect(h.writeState).toHaveBeenCalledTimes(1)
        expect(h.writeState.mock.calls[0][0].noticeShownAt).toBeDefined()
        // Fix: the notice reassigns the state cache, so a later opt-out write
        // does not clobber the just-persisted noticeShownAt ("shows twice" bug).
        t.setTelemetryDisabled(false)
        const lastWrite = h.writeState.mock.calls.at(-1)?.[0]
        expect(lastWrite?.noticeShownAt).toBeDefined()
      })
    } finally {
      write.mockRestore()
    }
  })

  it('does NOT print the notice when the state write fails — no once-per-run nag loop', async () => {
    // Persist-first: an unwritable HOME (sandboxed runner, read-only container)
    // must not print the disclosure on every invocation forever. No persist ⇒
    // no print ⇒ no telemetry ever (firstRun never clears) — dormant, not noisy.
    h.state.value = { anonymousId: 'a', telemetryDisabled: false } // firstRun
    const write = vi.spyOn(process.stderr, 'write').mockReturnValue(true)
    try {
      const t = await load()
      h.writeState.mockImplementation(() => {
        throw new Error('EROFS: read-only file system')
      })
      // The mocked ../state.js writeState wrapper re-throws through h.writeState.
      expect(() => t.maybeShowFirstRunNotice('npx stash')).not.toThrow()
      expect(write).not.toHaveBeenCalled()
    } finally {
      write.mockRestore()
    }
  })

  it('shutdownTelemetry resolves within the flush timeout when shutdown() hangs', async () => {
    // A black-holed endpoint: shutdown() never resolves. The bounded-flush
    // guarantee must still let the process continue via the ~1500ms timeout.
    // Real timers (fake timers don't drive the dynamic import); headroom below.
    h.shutdown.mockImplementation(() => new Promise<void>(() => {}))
    const t = await load()
    t.trackCommand({ command: 'init', success: true, durationMs: 1 })
    await expect(t.shutdownTelemetry()).resolves.toBeUndefined()
  }, 4000)
})
