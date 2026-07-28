import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CI_ENV_VARS } from '../../config/tty.js'
import {
  ALLOWED_PROP_KEYS,
  PLACEHOLDER_KEY,
  resolveStatus,
  sanitize,
  silentFetch,
  type TelemetryStatus,
} from '../index.js'
import type { TelemetryState } from '../state.js'

const enabledState: TelemetryState = {
  anonymousId: 'anon-1',
  telemetryDisabled: false,
}

/** The gates only run once a project key is present; otherwise it's dormant. */
function withKey(): void {
  vi.stubEnv('STASH_POSTHOG_KEY', 'phc_test_key')
}

/** Clear every env var that resolveStatus / isCiEnvBroad consult, INCLUDING
 * STASH_POSTHOG_KEY — a real value in the ambient shell (this repo sets it as a
 * GitHub Actions variable) would otherwise flip the dormant tests to enabled. */
function clearGateEnv(): void {
  for (const name of [
    'DO_NOT_TRACK',
    'STASH_TELEMETRY_DISABLED',
    'STASH_POSTHOG_KEY',
    ...CI_ENV_VARS,
  ]) {
    vi.stubEnv(name, '')
  }
}

function reasonOf(status: TelemetryStatus): string {
  return status.enabled ? 'enabled' : status.reason
}

describe('resolveStatus gates', () => {
  beforeEach(() => {
    clearGateEnv()
  })
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('is dormant (unconfigured) when no project key is set', () => {
    // No STASH_POSTHOG_KEY and the embedded literal is still the placeholder.
    expect(resolveStatus(enabledState)).toEqual({
      enabled: false,
      reason: 'unconfigured',
    })
  })

  it('an un-injected build (placeholder passthrough) stays dormant', () => {
    // Simulates a dev/fork/CI build: tsup baked in no key, so the resolved key
    // is the placeholder sentinel. Must read as unconfigured whatever the gates.
    vi.stubEnv('STASH_POSTHOG_KEY', PLACEHOLDER_KEY)
    expect(resolveStatus(enabledState)).toEqual({
      enabled: false,
      reason: 'unconfigured',
    })
  })

  it('a release-injected key is NOT mistaken for the placeholder → enabled', () => {
    // The regression the sentinel guards against: an injected key with no env
    // override must not read as unconfigured (the old `=== EMBEDDED_KEY` check
    // would have). Any real key differs from the placeholder.
    vi.stubEnv('STASH_POSTHOG_KEY', 'phc_realish_injected_key')
    expect(resolveStatus(enabledState)).toEqual({ enabled: true })
  })

  it('the placeholder sentinel matches the build-define identifier name', () => {
    // tsup replaces the `__STASH_POSTHOG_KEY__` identifier at release; the
    // sentinel must stay the identically-named string literal, or an un-injected
    // build would not be detected as dormant.
    expect(PLACEHOLDER_KEY).toBe('__STASH_POSTHOG_KEY__')
  })

  it('treats an empty/whitespace STASH_POSTHOG_KEY as unset → dormant', () => {
    // The `?? EMBEDDED_KEY` nullish fallback would let '' slip through and flip a
    // dormant build to enabled with an empty key; projectKey() trims it away.
    for (const value of ['', '   ']) {
      vi.stubEnv('STASH_POSTHOG_KEY', value)
      expect(resolveStatus(enabledState)).toEqual({
        enabled: false,
        reason: 'unconfigured',
      })
    }
  })

  it('is enabled with a key and no opt-out signals', () => {
    withKey()
    expect(resolveStatus(enabledState)).toEqual({ enabled: true })
  })

  it('DO_NOT_TRACK disables and outranks the persisted flag', () => {
    withKey()
    vi.stubEnv('DO_NOT_TRACK', '1')
    // Even with telemetry "enabled" in config, the env override wins.
    expect(reasonOf(resolveStatus(enabledState))).toBe('do-not-track')
  })

  it('STASH_TELEMETRY_DISABLED disables', () => {
    withKey()
    vi.stubEnv('STASH_TELEMETRY_DISABLED', 'true')
    expect(reasonOf(resolveStatus(enabledState))).toBe('stash-disabled')
  })

  it('DO_NOT_TRACK outranks STASH_TELEMETRY_DISABLED', () => {
    withKey()
    vi.stubEnv('DO_NOT_TRACK', '1')
    vi.stubEnv('STASH_TELEMETRY_DISABLED', '1')
    expect(reasonOf(resolveStatus(enabledState))).toBe('do-not-track')
  })

  it('auto-disables in CI', () => {
    withKey()
    vi.stubEnv('CI', 'true')
    expect(reasonOf(resolveStatus(enabledState))).toBe('ci')
  })

  it('honors a non-standard CI marker (GITHUB_ACTIONS)', () => {
    withKey()
    vi.stubEnv('GITHUB_ACTIONS', 'true')
    expect(reasonOf(resolveStatus(enabledState))).toBe('ci')
  })

  it('the persisted flag disables when no env override is present', () => {
    withKey()
    expect(
      reasonOf(resolveStatus({ ...enabledState, telemetryDisabled: true })),
    ).toBe('config')
  })

  it('treats DO_NOT_TRACK=0 / false / empty as not opted out', () => {
    withKey()
    for (const value of ['0', 'false', '']) {
      vi.stubEnv('DO_NOT_TRACK', value)
      expect(resolveStatus(enabledState)).toEqual({ enabled: true })
    }
  })

  it('honors DO_NOT_TRACK set to any other non-empty value', () => {
    withKey()
    // The convention is that setting the variable at all signals opt-out.
    for (const value of ['1', 'true', 'on', 'yes', 'please']) {
      vi.stubEnv('DO_NOT_TRACK', value)
      expect(reasonOf(resolveStatus(enabledState))).toBe('do-not-track')
    }
  })

  it('auto-disables for a provider marker without CI (GitLab)', () => {
    withKey()
    vi.stubEnv('GITLAB_CI', 'true')
    expect(reasonOf(resolveStatus(enabledState))).toBe('ci')
  })
})

describe('sanitize (property allowlist)', () => {
  it('drops any key not on the allowlist', () => {
    const out = sanitize({
      command: 'eql',
      subcommand: 'install',
      // Everything below is exactly what must never leave the machine.
      table: 'users',
      column: 'email',
      databaseUrl: 'postgres://secret@host/db',
      plaintext: 'alice@example.com',
      argv: ['--database-url', 'postgres://…'],
    })
    expect(out).toEqual({ command: 'eql', subcommand: 'install' })
  })

  it('keeps the full coarse event shape', () => {
    const event = {
      command: 'encrypt',
      subcommand: 'backfill',
      success: true,
      durationMs: 1234,
      errorType: undefined,
      cliVersion: '0.17.1',
      os: 'darwin',
      arch: 'arm64',
      nodeVersion: '22.0.0',
      caller: 'claude-code',
    }
    expect(sanitize(event)).toEqual(event)
    for (const key of Object.keys(event)) {
      expect(ALLOWED_PROP_KEYS.has(key)).toBe(true)
    }
  })

  it('the allowlist contains no identifying or payload fields', () => {
    for (const forbidden of [
      'table',
      'column',
      'schema',
      'databaseUrl',
      'connectionString',
      'plaintext',
      'ciphertext',
      'argv',
      'args',
      'value',
    ]) {
      expect(ALLOWED_PROP_KEYS.has(forbidden)).toBe(false)
    }
  })
})

describe('silentFetch (CIP-3587: failed sends must never print)', () => {
  const request = {
    method: 'POST' as const,
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('passes a successful response through untouched, forwarding url and options verbatim', async () => {
    const real = { status: 200, text: async () => 'ok', json: async () => ({}) }
    const fetchMock = vi.fn().mockResolvedValue(real)
    vi.stubGlobal('fetch', fetchMock)
    await expect(silentFetch('https://t.example', request)).resolves.toBe(real)
    // The options object (which carries the SDK's AbortSignal) must reach the
    // real fetch unmodified — dropping it would unbind requestTimeout and break
    // the bounded-flush guarantee the wrapper's doc comment promises.
    expect(fetchMock).toHaveBeenCalledWith('https://t.example', request)
  })

  it('swallows a network error into a stub 200 (no throw, nothing for the SDK to log)', async () => {
    // The repro: an unreachable endpoint. @posthog/core turns a rejected fetch
    // into PostHogFetchNetworkError and console.errors the full stack trace.
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new TypeError('fetch failed')),
    )
    const res = await silentFetch('https://t.example', request)
    expect(res.status).toBe(200)
    await expect(res.text()).resolves.toBe('')
  })

  it('swallows a timeout abort into a stub 200', async () => {
    // The SDK aborts via AbortController after requestTimeout; fetch rejects
    // with an AbortError DOMException, which must be swallowed like any other
    // network failure.
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockRejectedValue(
          new DOMException('This operation was aborted', 'AbortError'),
        ),
    )
    const res = await silentFetch('https://t.example', request)
    expect(res.status).toBe(200)
  })

  it('swallows an HTTP error status into a stub 200 and drains the real body', async () => {
    // status >= 400 makes the SDK throw PostHogFetchHttpError → same log path.
    // The discarded response's body must be cancelled so undici releases the
    // connection — a held socket outlives the bounded flush and keeps the
    // process alive after output.
    const cancel = vi.fn(async () => {})
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        status: 503,
        text: async () => '',
        json: async () => ({}),
        body: { cancel },
      }),
    )
    const res = await silentFetch('https://t.example', request)
    expect(res.status).toBe(200)
    expect(cancel).toHaveBeenCalledTimes(1)
  })
})
