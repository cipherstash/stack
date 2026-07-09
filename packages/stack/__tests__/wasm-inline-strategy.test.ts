/**
 * Offline unit tests for wasm-inline auth-strategy resolution.
 *
 * The WASM `Encryption` access-key path builds
 * `AccessKeyStrategy.create(workspaceCrn, accessKey)` — region derived from the
 * CRN, replacing the old `region` field. The only end-to-end exercise is the
 * Deno e2e (`e2e/wasm/roundtrip.test.ts`), which skips without real `CS_*`
 * secrets, so the wiring goes unchecked in the normal suite. These tests mock
 * `@cipherstash/auth/wasm-inline` and assert that the CRN reaches
 * `AccessKeyStrategy.create`, that an explicit `config.authStrategy` is used
 * verbatim, that the deprecated `config.strategy` alias still works (and warns),
 * and that the auth-strategy + `accessKey` mutual-exclusion guard fires. This
 * mirrors the Node entry's `config.authStrategy` contract.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    // `@cipherstash/auth` `0.41` `create` returns a `Result<Strategy, AuthFailure>`
    // (`{ data }` on success) — `resolveStrategy` unwraps `.data`.
    create: vi.fn(() => ({ data: { __mock: 'access-key-strategy' } })),
  },
  OidcFederationStrategy: class {},
}))

vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ({
  newClient: vi.fn(),
  encrypt: vi.fn(),
  decrypt: vi.fn(),
  isEncrypted: vi.fn(),
}))

import { AccessKeyStrategy } from '@cipherstash/auth/wasm-inline'
import {
  __resetStrategyDeprecationWarningForTests,
  resolveStrategy,
} from '../src/wasm-inline'

const CRN = 'crn:ap-southeast-2.aws:test-workspace'

// Silence + capture the deprecation warning and reset its once-per-process
// latch so each test asserts warning behaviour deterministically.
let warnSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  vi.clearAllMocks()
  __resetStrategyDeprecationWarningForTests()
  warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  warnSpy.mockRestore()
})

describe('wasm-inline resolveStrategy', () => {
  it('derives an AccessKeyStrategy from the workspace CRN', () => {
    const accessKeyOnly = { workspaceCrn: CRN, accessKey: 'CSAK.test' }
    // biome-ignore lint/suspicious/noExplicitAny: exercise the access-key arm of the discriminated union directly
    const strategy = resolveStrategy(accessKeyOnly as any)

    expect(vi.mocked(AccessKeyStrategy.create)).toHaveBeenCalledWith(
      CRN,
      'CSAK.test',
    )
    expect(strategy).toEqual({ __mock: 'access-key-strategy' })
    expect(warnSpy).not.toHaveBeenCalled()
  })

  it('throws when AccessKeyStrategy.create returns a failure Result', () => {
    // `@cipherstash/auth` `0.41` `create` returns `{ failure }` instead of
    // throwing — `resolveStrategy` must surface that as a loud construction
    // error naming the failure type and the underlying message, not forward
    // an unusable strategy.
    vi.mocked(AccessKeyStrategy.create).mockReturnValueOnce(
      // biome-ignore lint/suspicious/noExplicitAny: mock the 0.41 Result failure arm
      {
        failure: {
          type: 'InvalidWorkspaceCrn',
          error: new Error('unparseable CRN'),
        },
      } as any,
    )

    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: exercise the access-key arm directly
      resolveStrategy({ workspaceCrn: CRN, accessKey: 'CSAK.test' } as any),
    ).toThrowError(
      /failed to construct.*\(InvalidWorkspaceCrn\): unparseable CRN/,
    )
    // The guards passed and it reached the builder before failing.
    expect(vi.mocked(AccessKeyStrategy.create)).toHaveBeenCalledWith(
      CRN,
      'CSAK.test',
    )
    expect(warnSpy).not.toHaveBeenCalled()
  })

  it('uses an explicit config.authStrategy verbatim and never builds an access key', () => {
    const explicit = { getToken: vi.fn() }
    // biome-ignore lint/suspicious/noExplicitAny: exercise the authStrategy arm of the discriminated union directly
    const strategy = resolveStrategy({ authStrategy: explicit } as any)

    expect(strategy).toBe(explicit)
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
    expect(warnSpy).not.toHaveBeenCalled()
  })

  it('honours the deprecated config.strategy alias and warns', () => {
    const explicit = { getToken: vi.fn() }
    // biome-ignore lint/suspicious/noExplicitAny: exercise the deprecated strategy arm directly
    const strategy = resolveStrategy({ strategy: explicit } as any)

    expect(strategy).toBe(explicit)
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('`config.strategy` is deprecated'),
    )
  })

  it('warns at most once per process across repeated resolveStrategy calls', () => {
    // No reset between the two calls (the latch is only reset in beforeEach),
    // so they share one process-level latch — a regression that dropped the
    // `if (warnedStrategyDeprecated) return` guard would warn twice here.
    const explicit = { getToken: vi.fn() }
    // biome-ignore lint/suspicious/noExplicitAny: exercise the deprecated strategy arm directly
    resolveStrategy({ strategy: explicit } as any)
    // biome-ignore lint/suspicious/noExplicitAny: exercise the deprecated strategy arm directly
    resolveStrategy({ strategy: explicit } as any)

    expect(warnSpy).toHaveBeenCalledTimes(1)
  })

  it('prefers authStrategy over the deprecated strategy when both are set, and still warns', () => {
    const authStrategy = { getToken: vi.fn() }
    const strategy = { getToken: vi.fn() }
    const resolved = resolveStrategy(
      // biome-ignore lint/suspicious/noExplicitAny: both fields set — JS callers bypass the compile-time union
      { authStrategy, strategy } as any,
    )

    expect(resolved).toBe(authStrategy)
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('`config.strategy` is deprecated'),
    )
  })

  it('throws when the access-key arm is missing workspaceCrn or accessKey', () => {
    // JS callers bypass the compile-time union, so the no-strategy arm must
    // reject a missing CRN or access key instead of forwarding `undefined`
    // into `AccessKeyStrategy.create`.
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid — no strategy, no accessKey
      resolveStrategy({ workspaceCrn: CRN } as any),
    ).toThrowError(
      /`config\.workspaceCrn` and `config\.accessKey` are required/,
    )
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid — no strategy, no workspaceCrn
      resolveStrategy({ accessKey: 'CSAK.test' } as any),
    ).toThrowError(
      /`config\.workspaceCrn` and `config\.accessKey` are required/,
    )
    // The guard must short-circuit *before* building a strategy.
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
  })

  it('throws when both an auth strategy and accessKey are supplied', () => {
    const both = {
      workspaceCrn: CRN,
      accessKey: 'CSAK.test',
      authStrategy: { getToken: vi.fn() },
    }
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid — JS callers bypass the compile-time union
      resolveStrategy(both as any),
    ).toThrowError(
      /`config\.authStrategy` and `config\.accessKey` are mutually exclusive/,
    )
    // The guard must short-circuit *before* building a strategy.
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
  })

  it('throws when the deprecated strategy and accessKey are both supplied, naming `strategy`', () => {
    const both = {
      workspaceCrn: CRN,
      accessKey: 'CSAK.test',
      strategy: { getToken: vi.fn() },
    }
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid — JS callers bypass the compile-time union
      resolveStrategy(both as any),
    ).toThrowError(
      // Names the field the caller actually set, not the resolved `authStrategy`.
      /`config\.strategy` and `config\.accessKey` are mutually exclusive/,
    )
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
  })
})
