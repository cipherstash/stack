/**
 * `@cipherstash/prisma-next/stack` — one-call setup for the
 * `@cipherstash/stack` SDK against a Prisma Next contract.
 *
 * The three exports here form a layered API. Most consumers want
 * {@link cipherstashFromStack}; the two primitives are exposed for
 * advanced users who need to interpose custom logic.
 *
 * - {@link deriveStackSchemas} — pure function, contract.json →
 *   `EncryptedTable[]`. Use to construct `Encryption({ schemas })`
 *   yourself while keeping schemas in lockstep with the contract.
 *
 * - {@link createCipherstashSdk} — wraps an initialised stack
 *   `EncryptionClient` in the framework-native `CipherstashSdk`
 *   shape. Use when you've constructed the client yourself (custom
 *   keyset, multi-tenant routing).
 *
 * - {@link cipherstashFromStack} — the all-in-one factory.
 *   Returns ready-to-spread arrays for `postgres<Contract>({...})`.
 *
 * This subpath imports `@cipherstash/stack` directly. Consumers who
 * implement `CipherstashSdk` against a different SDK should use
 * `./runtime` and `./middleware` instead and pay no
 * `@cipherstash/stack` bundle cost.
 */

export type { ContractStorageView } from '../stack/derive-schemas'
export { deriveStackSchemas } from '../stack/derive-schemas'

export type {
  CipherstashFromStackOptions,
  CipherstashFromStackResult,
} from '../stack/from-stack'
export { cipherstashFromStack } from '../stack/from-stack'

export { createCipherstashSdk } from '../stack/sdk-adapter'
