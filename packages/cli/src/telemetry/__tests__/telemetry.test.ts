import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ALLOWED_PROP_KEYS,
  resolveStatus,
  sanitize,
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

/** Clear every env var that resolveStatus / isCI consult. */
function clearGateEnv(): void {
  for (const name of [
    'DO_NOT_TRACK',
    'STASH_TELEMETRY_DISABLED',
    'CI',
    'CONTINUOUS_INTEGRATION',
    'BUILD_NUMBER',
    'GITHUB_ACTIONS',
    'GITLAB_CI',
    'CIRCLECI',
    'TRAVIS',
    'BUILDKITE',
    'JENKINS_URL',
    'TEAMCITY_VERSION',
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

  it('treats DO_NOT_TRACK=0 as not opted out', () => {
    withKey()
    vi.stubEnv('DO_NOT_TRACK', '0')
    expect(resolveStatus(enabledState)).toEqual({ enabled: true })
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
