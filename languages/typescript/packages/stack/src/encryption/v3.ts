// Single import surface (`@cipherstash/stack/v3`): the v3 `types` namespace +
// table API + type helpers, alongside the client factory and its client type, so
// one import provides everything needed to author and use a schema.
export * from '@/eql/v3'
export type { EncryptionClient } from './client-v3'
export { Encryption } from './index'
