/**
 * Test fixtures for `@cipherstash/auth`.
 *
 * Factories live here so tests don't drift from the real `TokenResult` /
 * `AuthError` shapes. The actual `vi.mock(...)` calls have to sit at
 * top-level inside each test file (Vitest hoists them) — this module just
 * gives you the canned values to feed into those mocks.
 */

import type { AuthErrorCode, TokenResult } from '@cipherstash/auth'
import { vi } from 'vitest'

export function makeTokenResult(
  overrides: Partial<TokenResult> = {},
): TokenResult {
  return {
    token: 'test-bearer-token',
    subject: 'CS|test-user',
    workspaceId: 'WS_TEST',
    // Issuer that matches the `ap-southeast-2.aws` region entry in
    // commands/auth/login.ts so the `regions.find(...)` lookup resolves.
    issuer: 'https://ap-southeast-2.aws.cts.cipherstashmanaged.net',
    services: {
      zerokms: 'https://ap-southeast-2.aws.zerokms.cipherstashmanaged.net',
    },
    ...overrides,
  }
}

/** Build an `AuthError`-shaped error with a documented `.code` from `AuthErrorCode`. */
export function makeAuthError(
  code: AuthErrorCode,
  message?: string,
): Error & { code: AuthErrorCode } {
  const err = new Error(message ?? `auth error: ${code}`) as Error & {
    code: AuthErrorCode
  }
  err.code = code
  return err
}

/**
 * Stand-in for `DeviceCodeResult`. Includes vi-mocked `pollForToken` and
 * `openInBrowser` so callers can assert on call sequence and inject
 * resolutions/rejections per test.
 */
export function makeDeviceCodeResult(
  overrides: {
    userCode?: string
    verificationUri?: string
    verificationUriComplete?: string
    expiresIn?: number
    pollForToken?: ReturnType<typeof vi.fn>
    openInBrowser?: ReturnType<typeof vi.fn>
  } = {},
) {
  return {
    userCode: overrides.userCode ?? 'TEST-CODE',
    verificationUri: overrides.verificationUri ?? 'https://login.test/activate',
    verificationUriComplete:
      overrides.verificationUriComplete ??
      'https://login.test/activate?code=TEST-CODE',
    expiresIn: overrides.expiresIn ?? 600,
    pollForToken:
      overrides.pollForToken ??
      vi.fn().mockResolvedValue({
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        expiresIn: 3600,
      }),
    openInBrowser: overrides.openInBrowser ?? vi.fn().mockReturnValue(true),
  }
}
