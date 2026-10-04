/**
 * Pack metadata for the cipherstash extension.
 *
 * Mirrors `packages/3-extensions/pgvector/src/extension-metadata/descriptor-meta.ts` —
 * the metadata block that gets serialized into `contract.json`'s
 * `extensions.cipherstash` slot at emit time.
 *
 * SDK-free: the runtime descriptor layers SDK-bound codec descriptors
 * on top at execution time. The `codecDescriptors` slot here uses the
 * metadata-only target descriptors from `./codec-metadata` because
 * pack-meta consumers only read codec metadata (typeId, targetTypes,
 * traits, renderOutputType, nativeType, JSON projection); runtime
 * encode/decode always go through the SDK-bound v3 codecs produced by
 * `createV3CodecDescriptors` (see `../v3/codec-runtime-v3`).
 *
 * The control descriptor in `../exports/control.ts` spreads this pack
 * meta so the framework's contract emitter sees `authoring`,
 * `types.codecTypes.codecDescriptors`, and `types.storage` alongside
 * the contract-space and codec-lifecycle-hooks blocks already wired
 * by the codec lifecycle hook block.
 */

import { cipherstashAuthoringTypes } from '../contract-authoring'
import {
  cipherstashV3CodecDescriptors,
  cipherstashV3StorageRows,
} from './codec-metadata'
import {
  CIPHERSTASH_EXTENSION_VERSION,
  CIPHERSTASH_SPACE_ID,
} from './constants'

export { CIPHERSTASH_EXTENSION_VERSION }

export const cipherstashPackMeta = {
  kind: 'extension',
  id: CIPHERSTASH_SPACE_ID,
  familyId: 'sql',
  targetId: 'postgres',
  version: CIPHERSTASH_EXTENSION_VERSION,
  authoring: {
    type: cipherstashAuthoringTypes,
  },
  types: {
    codecTypes: {
      codecDescriptors: [
        // EQL v3 — all 40 catalog domains, derived (see codec-metadata.ts).
        ...cipherstashV3CodecDescriptors,
      ],
      // Drives the contract emitter to add
      //   `import type { CodecTypes as CipherstashTypes } from '@cipherstash/stack-prisma/codec-types'`
      // and to intersect `CipherstashTypes` into the generated
      // `CodecTypes` type alias. Without this slot the codec-id-keyed
      // type lookups (`CodecTypes['cipherstash/eql-v3/eql_v3_text@1']`)
      // collapse to `unknown` on the consumer side, and the
      // trait-dispatched operators (`eqlGt`, …) never surface on real
      // model accessors. Mirrors pgvector's `import:` slot.
      import: {
        package: '@cipherstash/stack-prisma/codec-types',
        named: 'CodecTypes',
        alias: 'CipherstashTypes',
      },
      // `renderOutputType` returns the bare envelope type name (e.g.
      // `EncryptedString`, `EncryptedNumber`) for parameterized
      // cipherstash columns; the contract emitter needs to import each
      // type alongside its occurrence so the generated `.d.ts`
      // typechecks cleanly. Mirrors pgvector's `Vector` typeImports
      // declaration.
      typeImports: [
        {
          package: '@cipherstash/stack-prisma/runtime',
          named: 'EncryptedString',
          alias: 'EncryptedString',
        },
        {
          package: '@cipherstash/stack-prisma/runtime',
          named: 'EncryptedBigInt',
          alias: 'EncryptedBigInt',
        },
        {
          package: '@cipherstash/stack-prisma/runtime',
          named: 'EncryptedDate',
          alias: 'EncryptedDate',
        },
        {
          package: '@cipherstash/stack-prisma/runtime',
          named: 'EncryptedBoolean',
          alias: 'EncryptedBoolean',
        },
        {
          package: '@cipherstash/stack-prisma/runtime',
          named: 'EncryptedJson',
          alias: 'EncryptedJson',
        },
        // v3-only envelope (every numeric v3 domain renders as
        // `EncryptedNumber`; the other v3 domains reuse the
        // version-neutral envelope classes already imported above).
        {
          package: '@cipherstash/stack-prisma/runtime',
          named: 'EncryptedNumber',
          alias: 'EncryptedNumber',
        },
      ],
    },
    queryOperationTypes: {
      import: {
        package: '@cipherstash/stack-prisma/operation-types',
        named: 'QueryOperationTypes',
        alias: 'CipherstashQueryOperationTypes',
      },
    },
    storage: [
      // EQL v3 — one row per catalog domain, each targeting its own
      // concrete `public.eql_v3_*` native type (see codec-metadata.ts).
      ...cipherstashV3StorageRows,
    ],
  },
} as const
