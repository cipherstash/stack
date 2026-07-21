/**
 * `@cipherstash/prisma-next/stack` — one-call setup for the
 * `@cipherstash/stack` SDK against a Prisma Next contract (EQL v3).
 *
 * Most consumers want {@link cipherstashFromStack}: it derives the v3
 * encryption schemas from your contract, constructs the
 * `@cipherstash/stack` `EncryptionV3` client from your `CS_*` env vars or
 * local profile, builds the SDK adapter, and returns ready-to-spread
 * `extensions` / `middleware` for `postgres<Contract>({...})`. The
 * remaining exports are the primitives it composes, for advanced users
 * who need to interpose custom logic (custom keyset, multi-tenant
 * routing).
 *
 * This subpath imports `@cipherstash/stack` directly. Consumers who
 * implement `CipherstashSdk` against a different SDK should use
 * `./runtime` instead and pay no `@cipherstash/stack` bundle cost.
 */

export type {
  CipherstashFromStackV3Options,
  CipherstashFromStackV3Result,
} from '../stack/from-stack-v3'
export { cipherstashFromStack } from '../stack/from-stack-v3'
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
