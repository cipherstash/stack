// Re-export main stack components for convenience

export { Encryption } from '@/encryption'
// Re-export encryption helpers for convenience
export {
  encryptedToPgComposite,
  isEncryptedPayload,
} from '@/encryption/helpers'
export { encryptedColumn, encryptedField, encryptedTable } from '@/schema'

// Re-export auth strategies for convenience. Pass one as `config.authStrategy`
// to `Encryption()` to control how ZeroKMS requests are authenticated — notably
// `OidcFederationStrategy` for per-user, identity-bound encryption (pair with
// `.withLockContext({ identityClaim })`). Re-exported so integrators don't need
// a separate `@cipherstash/auth` install.
//
// `@cipherstash/auth`'s Node entry is a CommonJS NAPI module whose exports come
// via `module.exports = { ...native }`. The spread defeats cjs-module-lexer, so
// Node's ESM loader can't see those names through a static `export { … } from`
// re-export (it throws "Named export not found"). We default-import the module
// (which IS `module.exports` at runtime, with every name present) and re-export
// each binding explicitly — both the value and, for the strategy classes, the
// instance type — so this works under real Node ESM, not just the bundler.
import auth from '@cipherstash/auth'

export const AccessKeyStrategy = auth.AccessKeyStrategy
export type AccessKeyStrategy = InstanceType<typeof auth.AccessKeyStrategy>
export const AutoStrategy = auth.AutoStrategy
export type AutoStrategy = InstanceType<typeof auth.AutoStrategy>
export const DeviceSessionStrategy = auth.DeviceSessionStrategy
export type DeviceSessionStrategy = InstanceType<
  typeof auth.DeviceSessionStrategy
>
export const OidcFederationStrategy = auth.OidcFederationStrategy
export type OidcFederationStrategy = InstanceType<
  typeof auth.OidcFederationStrategy
>

export type { AuthError, AuthErrorCode, TokenResult } from '@cipherstash/auth'
// Re-export types for convenience
export type { Encrypted } from '@/types'
