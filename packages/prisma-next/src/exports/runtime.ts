/**
 * Runtime-plane entry point for the CipherStash extension (EQL v3).
 *
 * Consumed at query time by application runtimes: the value envelopes
 * (`EncryptedString`, `EncryptedNumber`, `EncryptedBigInt`, …),
 * `decryptAll`, the CipherStash SDK shape the v3 codec runtime +
 * bulk-encrypt middleware depend on, and the v3 runtime descriptor /
 * operators.
 *
 * The runtime entry point is deliberately separate from `./control`
 * (descriptor, codec lifecycle hook, contract-space artefacts) so apps
 * that only emit migrations against cipherstash never load the runtime,
 * and apps that only run queries never load the migration-time
 * descriptor — the control plane and runtime plane are tree-shakable
 * along this seam.
 *
 * `createCipherstashV3RuntimeDescriptor({ sdk })` is the recommended
 * composition entry — it bundles the SDK-bound v3 codecs and the
 * runtime-plane `codecDescriptors` slot into a single
 * `SqlRuntimeExtensionDescriptor<'postgres'>`. The bulk-encrypt
 * middleware ships as `bulkEncryptMiddlewareV3(sdk)`.
 */

export type { DecryptAllOptions } from '../execution/decrypt-all'
export { decryptAll } from '../execution/decrypt-all'
export type {
  EncryptedBigIntFromInternalArgs,
  EncryptedBigIntHandle,
} from '../execution/envelope-bigint'
export { EncryptedBigInt } from '../execution/envelope-bigint'
export type {
  EncryptedBooleanFromInternalArgs,
  EncryptedBooleanHandle,
} from '../execution/envelope-boolean'
export { EncryptedBoolean } from '../execution/envelope-boolean'
export type {
  EncryptedDateFromInternalArgs,
  EncryptedDateHandle,
} from '../execution/envelope-date'
export { EncryptedDate } from '../execution/envelope-date'
export type {
  EncryptedJsonFromInternalArgs,
  EncryptedJsonHandle,
} from '../execution/envelope-json'
export { EncryptedJson } from '../execution/envelope-json'
export type {
  EncryptedStringFromInternalArgs,
  EncryptedStringHandle,
} from '../execution/envelope-string'
export { EncryptedString } from '../execution/envelope-string'
export type {
  CipherstashBulkDecryptArgs,
  CipherstashBulkEncryptArgs,
  CipherstashRoutingKey,
  CipherstashSdk,
  CipherstashSingleDecryptArgs,
} from '../execution/sdk'
// ---------------------------------------------------------------------------
// EQL v3 runtime surface — the package installs EQL v3 only.
// ---------------------------------------------------------------------------
export {
  CIPHERSTASH_V3_CODEC_IDS,
  CIPHERSTASH_V3_EXTENSION_VERSION,
  CIPHERSTASH_V3_SPACE_ID,
  type CipherstashV3CodecId,
  isCipherstashV3CodecId,
} from '../extension-metadata/constants-v3'
export { bulkEncryptMiddlewareV3 } from '../v3/bulk-encrypt-v3'
export {
  CipherstashV3CellCodec,
  type CipherstashV3CodecParams,
  cipherstashV3ParamsSchema,
  createV3CodecDescriptors,
} from '../v3/codec-runtime-v3'
export type {
  EncryptedNumberFromInternalArgs,
  EncryptedNumberHandle,
} from '../v3/envelope-number'
export { EncryptedNumber } from '../v3/envelope-number'
export {
  cipherstashV3QueryOperations,
  eqlAsc,
  eqlDesc,
  eqlJsonPathAsc,
  eqlJsonPathDesc,
} from '../v3/operators-v3'
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
export { v3FromDriver, v3ToDriver } from '../v3/wire-v3'
