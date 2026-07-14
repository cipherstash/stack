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
// ---------------------------------------------------------------------------
// EQL v3 (decision 1b: a SEPARATE entry point — a client is v2 or v3,
// never both; `cipherstashFromStackV3` rejects contracts carrying v2
// cipherstash codec ids).
// ---------------------------------------------------------------------------
export type {
  CipherstashFromStackV3Options,
  CipherstashFromStackV3Result,
} from '../stack/from-stack-v3'
export { cipherstashFromStackV3 } from '../stack/from-stack-v3'
export { createCipherstashSdk } from '../stack/sdk-adapter'
export type {
  V3ContractColumnEntry,
  V3ContractShape,
} from '../v3/derive-schemas-v3'
export {
  deriveStackSchemasV3,
  v3ContractColumnEntries,
} from '../v3/derive-schemas-v3'
export { assertV3SchemasAgree } from '../v3/from-stack-v3-validate'
export type { CipherstashV3Client } from '../v3/sdk-adapter-v3'
export { createCipherstashV3Sdk } from '../v3/sdk-adapter-v3'
