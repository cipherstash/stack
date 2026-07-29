/**
 * Tests for the optional `config.authStrategy` auth strategy (and its
 * deprecated `config.strategy` alias).
 *
 * protect-ffi (0.25+) lets `newClient` take an `AuthStrategy` (any
 * `{ getToken(): Promise<{ token }> }` object — the shape every
 * `@cipherstash/auth` strategy satisfies, including
 * `OidcFederationStrategy` for per-user identity-bound encryption).
 * `Encryption` exposes it via `config.authStrategy`; when provided it must
 * reach `newClient` as `opts.strategy` (the FFI's option name), and when
 * omitted the option must be absent so the default `auto` strategy is used.
 * The legacy `config.strategy` field is still honoured (with a runtime
 * deprecation warning) until it is removed.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { __resetStrategyDeprecationWarningForTests } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'
import type { AuthStrategy } from '@/types'

vi.mock('@cipherstash/protect-ffi', () => ({
  newClient: vi.fn(async () => ({ __mock: 'client' })),
}))

import * as ffi from '@cipherstash/protect-ffi'

const users = encryptedTable('users', {
  email: types.Text('email'),
})

// Silence + capture the deprecation warning, and reset its once-per-process
// latch, so each test asserts warning behaviour deterministically regardless
// of order. `afterEach` restores the spy even if an assertion throws mid-test.
let warnSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  vi.clearAllMocks()
  __resetStrategyDeprecationWarningForTests()
  warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  warnSpy.mockRestore()
})

describe('Encryption config.authStrategy', () => {
  it('forwards a supplied authStrategy to newClient', async () => {
    const authStrategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'service-token' })),
    }

    await Encryption({ schemas: [users], config: { authStrategy } })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(authStrategy)
  })

  it('passes the authStrategy alongside the credential clientOpts', async () => {
    const authStrategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'service-token' })),
    }

    await Encryption({
      schemas: [users],
      config: {
        authStrategy,
        workspaceCrn: 'crn:ap-southeast-2.aws:test-workspace',
        clientId: 'client-id',
        clientKey: 'client-key',
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(authStrategy)
    // clientKey is still required even when an authStrategy is supplied.
    expect(opts.clientOpts.clientKey).toBe('client-key')
    expect(opts.clientOpts.workspaceCrn).toBe(
      'crn:ap-southeast-2.aws:test-workspace',
    )
  })

  it('forwards an OidcFederationStrategy-shaped strategy to newClient', async () => {
    // Mirror `OidcFederationStrategy`'s public shape (getToken returning a
    // TokenResult) without loading the native `@cipherstash/auth` binding —
    // `Encryption` forwards the object opaquely, so its concrete type is
    // irrelevant to this wiring.
    const oidcStrategy: AuthStrategy = {
      getToken: vi.fn(async () => ({
        token: 'cts-service-token',
        subject: 'CS|auth0|user123',
        workspaceId: 'test-workspace',
        issuer: 'https://cts.example',
        services: { zerokms: 'https://zerokms.example' },
      })),
    }

    await Encryption({
      schemas: [users],
      config: { authStrategy: oidcStrategy },
    })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(oidcStrategy)
  })

  it('leaves strategy undefined when none is supplied', async () => {
    await Encryption({ schemas: [users] })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBeUndefined()
  })
})

describe('Encryption config.strategy (deprecated alias)', () => {
  it('still forwards a deprecated strategy to newClient and warns', async () => {
    const strategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'service-token' })),
    }

    await Encryption({ schemas: [users], config: { strategy } })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(strategy)
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('`config.strategy` is deprecated'),
    )
  })

  it('prefers authStrategy over the deprecated strategy when both are set, and still warns', async () => {
    const strategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'legacy-token' })),
    }
    const authStrategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'new-token' })),
    }

    await Encryption({
      schemas: [users],
      config: { strategy, authStrategy },
    })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(authStrategy)
    // The deprecated field is still present, so the nudge to remove it fires
    // even though `authStrategy` takes precedence.
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('`config.strategy` is deprecated'),
    )
  })

  it('does not warn when only authStrategy is supplied', async () => {
    const authStrategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'new-token' })),
    }

    await Encryption({ schemas: [users], config: { authStrategy } })

    expect(warnSpy).not.toHaveBeenCalled()
  })

  it('warns at most once per process across repeated Encryption calls', async () => {
    // No reset between the two calls (the latch is only reset in beforeEach),
    // so they share one process-level latch — a regression that dropped the
    // `if (warnedStrategyDeprecated) return` guard would warn twice here.
    const strategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'service-token' })),
    }

    await Encryption({ schemas: [users], config: { strategy } })
    await Encryption({ schemas: [users], config: { strategy } })

    expect(warnSpy).toHaveBeenCalledTimes(1)
  })
})

describe('Encryption v3 wire format', () => {
  // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
  const lastNewClientOpts = () =>
    vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any

  it('always constructs the FFI client with eqlVersion 3', async () => {
    await Encryption({ schemas: [users] })

    expect(lastNewClientOpts().eqlVersion).toBe(3)
  })

  it('rejects a non-v3 schema before constructing the FFI client', async () => {
    const legacyTable = {
      tableName: 'legacy_users',
      build: () => ({ tableName: 'legacy_users', columns: {} }),
    }
    await expect(
      Encryption({ schemas: [legacyTable as never] }),
    ).rejects.toThrow(/is not an EQL v3 table/)
    expect(ffi.newClient).not.toHaveBeenCalled()
  })

  it('rejects the removed config.eqlVersion escape hatch at runtime', async () => {
    await expect(
      Encryption({
        schemas: [users],
        config: { eqlVersion: 2 } as never,
      }),
    ).rejects.toThrow(/config\.eqlVersion.*removed/)

    expect(ffi.newClient).not.toHaveBeenCalled()
  })
})
