import { beforeEach, describe, expect, it, vi } from 'vitest'
import { makeTokenResult } from '../../../tests/helpers/auth-mock.js'

// Mock only `@cipherstash/auth` here — we want the real `resolveExistingAuth`
// under test, with a stub for the NAPI strategy it constructs.
const napi = vi.hoisted(() => ({
  getToken: vi.fn(),
}))
vi.mock('@cipherstash/auth', () => ({
  default: {
    AutoStrategy: { detect: () => ({ getToken: napi.getToken }) },
    AccessKeyStrategy: { create: vi.fn() },
    OAuthStrategy: { fromProfile: vi.fn() },
    beginDeviceCodeFlow: vi.fn(),
    bindClientDevice: vi.fn(),
  },
}))

const { resolveExistingAuth } = await import('../strategy.js')

describe('resolveExistingAuth', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('maps a known issuer to the matching region label', async () => {
    napi.getToken.mockResolvedValueOnce(makeTokenResult())

    const result = await resolveExistingAuth()

    expect(result).toEqual({
      workspace: 'WS_TEST',
      regionLabel: 'ap-southeast-2 (Sydney, Australia)',
    })
  })

  it('returns regionLabel="unknown" when the issuer matches no region', async () => {
    napi.getToken.mockResolvedValueOnce(
      makeTokenResult({ issuer: 'https://nowhere.example.com' }),
    )

    const result = await resolveExistingAuth()

    expect(result).toEqual({
      workspace: 'WS_TEST',
      regionLabel: 'unknown',
    })
  })

  // The catch in resolveExistingAuth is a deliberate "treat any auth error as
  // not authenticated" — this is a regression net for the day someone
  // narrows it. The codes come from `@cipherstash/auth/index.d.ts:7-22`.
  it.each([
    'NOT_AUTHENTICATED',
    'EXPIRED_TOKEN',
    'INVALID_ACCESS_KEY',
    'MISSING_WORKSPACE_CRN',
    'REQUEST_ERROR',
  ])('returns undefined when getToken rejects with %s', async (code) => {
    napi.getToken.mockRejectedValueOnce(
      Object.assign(new Error(code), { code }),
    )

    const result = await resolveExistingAuth()

    expect(result).toBeUndefined()
  })
})
