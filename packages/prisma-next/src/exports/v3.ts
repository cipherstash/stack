/**
 * `@cipherstash/prisma-next/v3` — the complete EQL v3 surface in one
 * import (decision 1b: v3 is a SEPARATE entry point from the v2
 * `./runtime` / `./stack` composition — a client is v2 or v3, never
 * both; the two runtime descriptors collide if co-registered).
 *
 * Most consumers want exactly one symbol from here:
 *
 *   const cipherstash = await cipherstashFromStackV3({ contractJson })
 *
 * The remaining exports are the primitives that factory composes —
 * schema derivation, the SDK adapter, the runtime descriptor, the
 * bulk-encrypt middleware, envelopes, and the query-term seam — for
 * advanced users interposing custom logic (multi-tenant SDK routing,
 * a non-stack `CipherstashSdk` implementation, …).
 *
 * Bundle note: this entry re-exports `cipherstashFromStackV3`, which
 * imports `@cipherstash/stack`. Consumers who need an SDK-free runtime
 * plane (custom `CipherstashSdk`) should import from `./runtime`
 * instead — its v3 exports carry no `@cipherstash/stack` client
 * import-edge.
 */

// v3's extension identity + the pinned codec-id union.
export {
  CIPHERSTASH_V3_CODEC_IDS,
  CIPHERSTASH_V3_EXTENSION_VERSION,
  CIPHERSTASH_V3_SPACE_ID,
  type CipherstashV3CodecId,
  isCipherstashV3CodecId,
} from '../extension-metadata/constants-v3'
// The v3-only entry point + composition primitives.
export type {
  CipherstashFromStackV3Options,
  CipherstashFromStackV3Result,
} from '../stack/from-stack-v3'
export { cipherstashFromStackV3 } from '../stack/from-stack-v3'
// User-facing value envelopes (version-neutral classes + the v3-only
// EncryptedNumber).
export * from '../v3/barrel'
export { bulkEncryptMiddlewareV3 } from '../v3/bulk-encrypt-v3'
export {
  CipherstashV3CellCodec,
  type CipherstashV3CodecParams,
  cipherstashV3ParamsSchema,
  createV3CodecDescriptors,
} from '../v3/codec-runtime-v3'
export type {
  V3ContractColumnEntry,
  V3ContractShape,
} from '../v3/derive-schemas-v3'
export {
  deriveStackSchemasV3,
  v3ContractColumnEntries,
} from '../v3/derive-schemas-v3'
export { assertV3SchemasAgree } from '../v3/from-stack-v3-validate'
// Query operators (registered by the runtime descriptor) + the
// free-standing ORDER BY helpers.
export {
  cipherstashV3QueryOperations,
  eqlAsc,
  eqlDesc,
} from '../v3/operators-v3'
// The query-term seam (consumed by custom CipherstashSdk implementations).
export {
  EncryptionOperatorError,
  markV3QueryTerm,
  type V3QueryTermType,
  v3QueryTermTypeOf,
} from '../v3/query-term'
export {
  type CreateCipherstashV3RuntimeDescriptorOptions,
  createCipherstashV3RuntimeDescriptor,
} from '../v3/runtime-v3'
export type { CipherstashV3Client } from '../v3/sdk-adapter-v3'
export { createCipherstashV3Sdk } from '../v3/sdk-adapter-v3'
// v3 wire helpers (plain JSONB).
export { v3FromDriver, v3ToDriver } from '../v3/wire-v3'
