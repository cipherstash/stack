/**
 * Runtime-plane entry point for the CipherStash extension.
 *
 * Consumed at query time by application runtimes that need to encode /
 * decode `cipherstash/string@1` columns (envelope class) and talk to the
 * CipherStash SDK shape the codec runtime + bulk-encrypt middleware
 * depend on.
 *
 * The runtime entry point is deliberately separate from `./control`
 * (descriptor, codec lifecycle hook, contract-space artefacts) so apps
 * that only emit migrations against cipherstash never load the runtime,
 * and apps that only run queries never load the migration-time
 * descriptor — the control plane and runtime plane are tree-shakable
 * along this seam.
 *
 * `createCipherstashRuntimeDescriptor({ sdk })` is the recommended
 * composition entry — it bundles the SDK-bound codec, the parameterized
 * codec descriptor, and the runtime-plane `codecInstances` slot into a
 * single `SqlRuntimeExtensionDescriptor<'postgres'>` mirroring
 * pgvector's `runtime.ts` precedent. The bulk-encrypt middleware ships
 * separately at `@prisma-next/extension-cipherstash/middleware` because
 * `SqlRuntimeExtensionDescriptor` does not own a middleware slot;
 * consumers register it via `new PostgresRuntimeImpl({ middleware:
 * [bulkEncryptMiddleware(sdk)] })` (or their target facade's
 * `middleware` option).
 */

import type { SqlRuntimeExtensionDescriptor } from '@prisma-next/sql-runtime'
import { cipherstashQueryOperations } from '../execution/operators'
import { createParameterizedCodecDescriptors } from '../execution/parameterized'
import type { CipherstashSdk } from '../execution/sdk'
import {
  CIPHERSTASH_EXTENSION_VERSION,
  CIPHERSTASH_SPACE_ID,
} from '../extension-metadata/constants'

export type { CipherstashStringCodec } from '../execution/codec-runtime'
export {
  CIPHERSTASH_STRING_CODEC_ID,
  CipherstashCellCodec,
  createCipherstashBigIntCodec,
  createCipherstashBooleanCodec,
  createCipherstashDateCodec,
  createCipherstashDoubleCodec,
  createCipherstashJsonCodec,
  createCipherstashStringCodec,
} from '../execution/codec-runtime'
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
  EncryptedDoubleFromInternalArgs,
  EncryptedDoubleHandle,
} from '../execution/envelope-double'
export { EncryptedDouble } from '../execution/envelope-double'
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
export {
  cipherstashAsc,
  cipherstashDesc,
  cipherstashJsonbGet,
  cipherstashJsonbPathQueryFirst,
} from '../execution/helpers'
export type {
  CipherstashAnyParams,
  CipherstashBooleanParams,
  CipherstashDateParams,
  CipherstashJsonParams,
  CipherstashNumericParams,
  CipherstashStringParams,
} from '../execution/parameterized'
export {
  createParameterizedCodecDescriptors,
  encryptedBigIntParamsSchema,
  encryptedBooleanParamsSchema,
  encryptedDateParamsSchema,
  encryptedDoubleParamsSchema,
  encryptedJsonParamsSchema,
  encryptedStringParamsSchema,
  renderEncryptedBigIntOutputType,
  renderEncryptedBooleanOutputType,
  renderEncryptedDateOutputType,
  renderEncryptedDoubleOutputType,
  renderEncryptedJsonOutputType,
  renderEncryptedStringOutputType,
} from '../execution/parameterized'
export type {
  CipherstashBulkDecryptArgs,
  CipherstashBulkEncryptArgs,
  CipherstashRoutingKey,
  CipherstashSdk,
  CipherstashSingleDecryptArgs,
} from '../execution/sdk'
export {
  CIPHERSTASH_BIGINT_CODEC_ID,
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_DATE_CODEC_ID,
  CIPHERSTASH_DOUBLE_CODEC_ID,
  CIPHERSTASH_JSON_CODEC_ID,
} from '../extension-metadata/constants'
// ---------------------------------------------------------------------------
// EQL v3 runtime surface (decision 1b: a SEPARATE extension descriptor
// under v3's own id — never co-register it with the v2 descriptor
// above; the shared `cipherstash*` method names collide in the flat
// OperationRegistry).
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
  cipherstashV3Asc,
  cipherstashV3Desc,
  cipherstashV3QueryOperations,
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

export { CIPHERSTASH_EXTENSION_VERSION }

export interface CreateCipherstashRuntimeDescriptorOptions {
  readonly sdk: CipherstashSdk
}

/**
 * Compose the SDK-bound codec runtime + parameterized codec descriptors
 * + runtime-plane codec-instances metadata into a single
 * `SqlRuntimeExtensionDescriptor<'postgres'>`.
 *
 * The descriptor is per-SDK: cipherstash's codec captures the SDK at
 * `decode` time (read-side single-cell `decrypt`) and the bulk-encrypt
 * middleware captures it at `beforeExecute` time (write-side bulk
 * round-trip). Multi-tenant deployments construct one descriptor per
 * tenant SDK so per-tenant key material never crosses runtimes.
 *
 * Mirrors `packages/3-extensions/pgvector/src/exports/runtime.ts` —
 * pgvector's vectorRuntimeDescriptor is a static default-export because
 * its codec is fully stateless; cipherstash needs the factory wrapper
 * because the codec depends on `sdk`.
 */
export function createCipherstashRuntimeDescriptor(
  opts: CreateCipherstashRuntimeDescriptorOptions,
): SqlRuntimeExtensionDescriptor<'postgres'> {
  const { sdk } = opts
  const parameterizedDescriptors = createParameterizedCodecDescriptors(sdk)

  return {
    kind: 'extension' as const,
    id: CIPHERSTASH_SPACE_ID,
    version: CIPHERSTASH_EXTENSION_VERSION,
    familyId: 'sql' as const,
    targetId: 'postgres' as const,
    types: {
      codecTypes: {
        codecDescriptors: parameterizedDescriptors,
      },
    },
    codecs: () => parameterizedDescriptors,
    queryOperations: () => cipherstashQueryOperations(),
    create() {
      return {
        familyId: 'sql' as const,
        targetId: 'postgres' as const,
      }
    },
  }
}
