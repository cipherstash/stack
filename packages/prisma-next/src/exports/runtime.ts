/**
 * Runtime-plane entry point for the CipherStash extension.
 *
 * Consumed at query time by application runtimes that need to encode /
 * decode any cipherstash encrypted column — the six v2 storage codecs
 * (`cipherstash/string@1`, `double@1`, `bigint@1`, `date@1`, `boolean@1`,
 * `json@1`) PLUS the EQL v3 string codec (`cipherstash/string-v3@1`) —
 * via their envelope classes, and talk to the CipherStash SDK shape the
 * codec runtime + bulk-encrypt middleware depend on.
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
 * separately at `@cipherstash/prisma-next/middleware` because
 * `SqlRuntimeExtensionDescriptor` does not own a middleware slot;
 * consumers register it via `createRuntime({ middleware:
 * [bulkEncryptMiddleware(sdk)] })`.
 */

import type { SqlRuntimeExtensionDescriptor } from '@prisma-next/sql-runtime';
import { cipherstashQueryOperations } from '../execution/operators';
import { createParameterizedCodecDescriptors } from '../execution/parameterized';
import type { CipherstashSdk } from '../execution/sdk';
import {
  CIPHERSTASH_EXTENSION_VERSION,
  CIPHERSTASH_SPACE_ID,
} from '../extension-metadata/constants';

export type { CipherstashStringCodec } from '../execution/codec-runtime';
export {
  CIPHERSTASH_STRING_CODEC_ID,
  CipherstashCellCodec,
  createCipherstashBigIntCodec,
  createCipherstashBooleanCodec,
  createCipherstashDateCodec,
  createCipherstashDoubleCodec,
  createCipherstashJsonCodec,
  createCipherstashStringCodec,
  createCipherstashStringV3Codec,
} from '../execution/codec-runtime';
export type { DecryptAllOptions } from '../execution/decrypt-all';
export { decryptAll } from '../execution/decrypt-all';
export type {
  EncryptedBigIntFromInternalArgs,
  EncryptedBigIntHandle,
} from '../execution/envelope-bigint';
export { EncryptedBigInt } from '../execution/envelope-bigint';
export type {
  EncryptedBooleanFromInternalArgs,
  EncryptedBooleanHandle,
} from '../execution/envelope-boolean';
export { EncryptedBoolean } from '../execution/envelope-boolean';
export type {
  EncryptedDateFromInternalArgs,
  EncryptedDateHandle,
} from '../execution/envelope-date';
export { EncryptedDate } from '../execution/envelope-date';
export type {
  EncryptedDoubleFromInternalArgs,
  EncryptedDoubleHandle,
} from '../execution/envelope-double';
export { EncryptedDouble } from '../execution/envelope-double';
export type {
  EncryptedJsonFromInternalArgs,
  EncryptedJsonHandle,
} from '../execution/envelope-json';
export { EncryptedJson } from '../execution/envelope-json';
export type {
  EncryptedStringFromInternalArgs,
  EncryptedStringHandle,
} from '../execution/envelope-string';
export { EncryptedString } from '../execution/envelope-string';
export {
  cipherstashAsc,
  cipherstashDesc,
  cipherstashJsonbGet,
  cipherstashJsonbPathQueryFirst,
} from '../execution/helpers';
export { queryTypeForIndex } from '../execution/operators';
export type {
  CipherstashAnyParams,
  CipherstashBooleanParams,
  CipherstashDateParams,
  CipherstashJsonParams,
  CipherstashNumericParams,
  CipherstashStringParams,
  CipherstashStringV3Params,
} from '../execution/parameterized';
export {
  createParameterizedCodecDescriptors,
  encryptedBigIntParamsSchema,
  encryptedBooleanParamsSchema,
  encryptedDateParamsSchema,
  encryptedDoubleParamsSchema,
  encryptedJsonParamsSchema,
  encryptedStringParamsSchema,
  encryptedStringV3ParamsSchema,
  renderEncryptedBigIntOutputType,
  renderEncryptedBooleanOutputType,
  renderEncryptedDateOutputType,
  renderEncryptedDoubleOutputType,
  renderEncryptedJsonOutputType,
  renderEncryptedStringOutputType,
  renderEncryptedStringV3OutputType,
} from '../execution/parameterized';
export type {
  CipherstashBulkDecryptArgs,
  CipherstashBulkEncryptArgs,
  CipherstashBulkEncryptQueryArgs,
  CipherstashRoutingKey,
  CipherstashSdk,
  CipherstashSingleDecryptArgs,
} from '../execution/sdk';
export type { V3DataType, V3Index } from '../v3/domain-map';
export {
  CIPHERSTASH_BIGINT_CODEC_ID,
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_DATE_CODEC_ID,
  CIPHERSTASH_DOUBLE_CODEC_ID,
  CIPHERSTASH_JSON_CODEC_ID,
  CIPHERSTASH_STRING_V3_CODEC_ID,
} from '../extension-metadata/constants';

export { CIPHERSTASH_EXTENSION_VERSION };

export interface CreateCipherstashRuntimeDescriptorOptions {
  readonly sdk: CipherstashSdk;
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
  const { sdk } = opts;
  const parameterizedDescriptors = createParameterizedCodecDescriptors(sdk);

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
      };
    },
  };
}
