// Re-export main stack components for convenience

export { Encryption } from '@/encryption'
// Re-export encryption helpers for convenience
export {
  encryptedToPgComposite,
  isEncryptedPayload,
} from '@/encryption/helpers'
export { encryptedColumn, encryptedField, encryptedTable } from '@/schema'

// Re-export auth strategies for convenience. Pass one as `config.strategy` to
// `Encryption()` to control how ZeroKMS requests are authenticated — notably
// `OidcFederationStrategy` for per-user, identity-bound encryption (pair with
// `.withLockContext({ identityClaim })`). Re-exported so integrators don't need
// a separate `@cipherstash/auth` install.
export {
  AccessKeyStrategy,
  AutoStrategy,
  DeviceSessionStrategy,
  OidcFederationStrategy,
} from '@cipherstash/auth'

// Re-export types for convenience
export type { Encrypted } from '@/types'
export type { AuthError, AuthErrorCode, TokenResult } from '@cipherstash/auth'
