/**
 * Offline unit tests for wasm-inline auth-strategy resolution.
 *
 * The WASM `Encryption` access-key path builds
 * `AccessKeyStrategy.create(workspaceCrn, accessKey)` — region derived from the
 * CRN, replacing the old `region` field. The only end-to-end exercise is the
 * Deno e2e (`e2e/wasm/roundtrip.test.ts`), which skips without real `CS_*`
 * secrets, so the wiring goes unchecked in the normal suite. These tests mock
 * `@cipherstash/auth/wasm-inline` and assert that the CRN reaches
 * `AccessKeyStrategy.create`, that an explicit `config.strategy` is used
 * verbatim, and that the `strategy` + `accessKey` mutual-exclusion guard fires.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    create: vi.fn(() => ({ __mock: 'access-key-strategy' })),
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
import { resolveStrategy } from '../src/wasm-inline'

const CRN = 'crn:ap-southeast-2.aws:test-workspace'

beforeEach(() => {
  vi.clearAllMocks()
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
  })

  it('uses an explicit config.strategy verbatim and never builds an access key', () => {
    const explicit = { getToken: vi.fn() }
    // biome-ignore lint/suspicious/noExplicitAny: exercise the strategy arm of the discriminated union directly
    const strategy = resolveStrategy({ strategy: explicit } as any)

    expect(strategy).toBe(explicit)
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
  })

  it('throws when the access-key arm is missing workspaceCrn or accessKey', () => {
    // JS callers bypass the compile-time union, so the no-strategy arm must
    // reject a missing CRN or access key instead of forwarding `undefined`
    // into `AccessKeyStrategy.create`.
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid — no strategy, no accessKey
      resolveStrategy({ workspaceCrn: CRN } as any),
    ).toThrowError(/`config\.workspaceCrn` and `config\.accessKey` are required/)
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid — no strategy, no workspaceCrn
      resolveStrategy({ accessKey: 'CSAK.test' } as any),
    ).toThrowError(/`config\.workspaceCrn` and `config\.accessKey` are required/)
    // The guard must short-circuit *before* building a strategy.
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
  })

  it('throws when both strategy and accessKey are supplied', () => {
    const both = {
      workspaceCrn: CRN,
      accessKey: 'CSAK.test',
      strategy: { getToken: vi.fn() },
    }
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid — JS callers bypass the compile-time union
      resolveStrategy(both as any),
    ).toThrowError(/mutually exclusive/)
    // The guard must short-circuit *before* building a strategy.
    expect(vi.mocked(AccessKeyStrategy.create)).not.toHaveBeenCalled()
  })
})
