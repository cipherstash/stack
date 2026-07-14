/**
 * The v3 runtime extension descriptor —
 * `createCipherstashV3RuntimeDescriptor({ sdk })`, the v3 twin of
 * `../exports/runtime.ts`'s `createCipherstashRuntimeDescriptor`.
 *
 * Composes the SDK-bound v3 codec descriptors (Task 4, one per catalog
 * domain) and the v3 query operations (Task 6) into a single
 * `SqlRuntimeExtensionDescriptor<'postgres'>` under v3's OWN extension
 * id/version (decision 1b) — NOT the v2 `CIPHERSTASH_SPACE_ID` /
 * `CIPHERSTASH_EXTENSION_VERSION`. The registered method names
 * (`cipherstashEq`, …) are identical to the v2 set, so the v2 and v3
 * descriptors must NEVER be co-registered in one client: the flat,
 * method-name-keyed `OperationRegistry` throws on the shared names
 * (pinned in `test/v3/operator-gating-v3.test.ts`). A client is v2 or
 * v3, never both.
 *
 * The v3 bulk-encrypt middleware ships separately
 * (`bulkEncryptMiddlewareV3(sdk)`) because
 * `SqlRuntimeExtensionDescriptor` does not own a middleware slot —
 * same split as v2.
 */

import type { SqlRuntimeExtensionDescriptor } from '@prisma-next/sql-runtime'
import type { CipherstashSdk } from '../execution/sdk'
import {
  CIPHERSTASH_V3_EXTENSION_VERSION,
  CIPHERSTASH_V3_SPACE_ID,
} from '../extension-metadata/constants-v3'
import { createV3CodecDescriptors } from './codec-runtime-v3'
import { cipherstashV3QueryOperations } from './operators-v3'

export interface CreateCipherstashV3RuntimeDescriptorOptions {
  readonly sdk: CipherstashSdk
}

/**
 * Compose the SDK-bound v3 codec descriptors + query operations into a
 * single `SqlRuntimeExtensionDescriptor<'postgres'>`.
 *
 * The descriptor is per-SDK: each codec captures the SDK for the
 * read-side decrypt path. Multi-tenant deployments construct one
 * descriptor per tenant SDK so per-tenant key material never crosses
 * runtimes (same contract as v2).
 */
export function createCipherstashV3RuntimeDescriptor(
  opts: CreateCipherstashV3RuntimeDescriptorOptions,
): SqlRuntimeExtensionDescriptor<'postgres'> {
  const descriptors = createV3CodecDescriptors(opts.sdk)

  return {
    kind: 'extension' as const,
    id: CIPHERSTASH_V3_SPACE_ID,
    version: CIPHERSTASH_V3_EXTENSION_VERSION,
    familyId: 'sql' as const,
    targetId: 'postgres' as const,
    types: {
      codecTypes: {
        codecDescriptors: descriptors,
      },
    },
    codecs: () => descriptors,
    queryOperations: () => cipherstashV3QueryOperations(),
    create() {
      return {
        familyId: 'sql' as const,
        targetId: 'postgres' as const,
      }
    },
  }
}
