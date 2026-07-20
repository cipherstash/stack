/**
 * SDK-free codec used in pack-meta (`cipherstashPackMeta.types.codecTypes
 * .codecInstances`). Pack-meta consumers only read codec *metadata*
 * (`typeId`, `targetTypes`, `traits`, `renderOutputType`) at contract
 * emit time — they never call `encode`/`decode`.
 *
 * The SDK-bound runtime codec for actual `encode`/`decode` lives in
 * `../v3/codec-runtime-v3`; it is resolved through the runtime
 * descriptor's `codecDescriptors` at runtime instead of through
 * pack-meta's `codecInstances`.
 *
 * Keeping the SDK-free metadata in its own module — and *not* importing
 * the runtime envelope classes — preserves the control vs runtime
 * split. Control-plane consumers (`exports/control.ts`,
 * `exports/pack.ts`) pull this file but never touch the envelope, the
 * SDK interface, or the bulk-encrypt middleware. The bundling-isolation
 * test pins this property by snapshotting that the control entry's
 * chunk graph does not transitively load `envelope-*.mjs`.
 *
 * `encode`/`decode` throw with a clear hint in the misuse case so
 * accidental wiring of the metadata codec into a real runtime path
 * surfaces immediately instead of silently no-op'ing.
 */

import type { JsonValue } from '@prisma-next/contract/types'
import {
  type AnyCodecDescriptor,
  CodecImpl,
  type CodecTrait,
} from '@prisma-next/framework-components/codec'
import {
  envelopeTypeNameForCastAs,
  V3_DOMAIN_META_BY_CODEC_ID,
  type V3DomainMeta,
} from '../v3/catalog'
import { v3TraitsForCapabilities } from './constants-v3'

class CipherstashCodecMetadata extends CodecImpl<
  string,
  readonly [],
  unknown,
  unknown
> {
  readonly #typeName: string

  constructor(descriptor: AnyCodecDescriptor, typeName: string) {
    super(descriptor)
    this.#typeName = typeName
  }

  async encode(): Promise<unknown> {
    throw new Error(
      'cipherstash codec: encode called on the pack-meta metadata codec. ' +
        'Construct a runtime descriptor via `createCipherstashV3RuntimeDescriptor({ sdk })` and use that instead.',
    )
  }

  async decode(): Promise<unknown> {
    throw new Error(
      'cipherstash codec: decode called on the pack-meta metadata codec. ' +
        'Construct a runtime descriptor via `createCipherstashV3RuntimeDescriptor({ sdk })` and use that instead.',
    )
  }

  encodeJson(): JsonValue {
    const marker = `$${this.#typeName.charAt(0).toLowerCase()}${this.#typeName.slice(1)}`
    return { [marker]: '<opaque>' } as JsonValue
  }

  decodeJson(): unknown {
    throw new Error(
      'cipherstash codec: decodeJson is not supported; envelopes do not round-trip through JSON.',
    )
  }
}

// ---------------------------------------------------------------------------
// EQL v3 — one metadata codec per catalog domain (all 40), DERIVED from the
// catalog (never hand-listed) so pack-meta can never drift from what the
// runtime registers. Mirrors the truthful metadata of the runtime auxiliary
// descriptors in `../v3/codec-runtime-v3.ts` (traits from capabilities,
// concrete `public.eql_v3_*` native type, `isParameterized: true` for the
// static `{ castAs, capabilities }` typeParams block v3 authoring emits) —
// minus the SDK-bound encode/decode, which pack-meta consumers never call.
// The catalog import stays SDK/envelope-free, preserving the control-vs-
// runtime bundling split this module's header describes.
// ---------------------------------------------------------------------------

function makeV3MetadataDescriptor(
  codecId: string,
  meta: V3DomainMeta,
  typeName: string,
): AnyCodecDescriptor {
  return {
    codecId,
    // Type-level adapter into the framework's closed `CodecTrait` union —
    // same rationale as `v3CodecTraits` in `../v3/codec-runtime-v3.ts`.
    traits: v3TraitsForCapabilities(meta.capabilities) as readonly CodecTrait[],
    targetTypes: [meta.nativeType],
    meta: { db: { sql: { postgres: { nativeType: meta.nativeType } } } },
    paramsSchema: {
      '~standard': {
        version: 1,
        vendor: 'cipherstash',
        validate: (value: unknown) => ({ value }),
      },
    },
    isParameterized: true,
    renderOutputType: () => typeName,
    factory: () => () => {
      throw new Error(
        'cipherstash codec: metadata descriptor factory is not callable',
      )
    },
  }
}

/** All 40 v3 metadata codecs, in catalog order. */
export const cipherstashV3CodecMetadataInstances: readonly CipherstashCodecMetadata[] =
  [...V3_DOMAIN_META_BY_CODEC_ID.entries()].map(([codecId, meta]) => {
    const typeName = envelopeTypeNameForCastAs(meta.castAs)
    return new CipherstashCodecMetadata(
      makeV3MetadataDescriptor(codecId, meta, typeName),
      typeName,
    )
  })

/** Pack-meta `types.storage` rows for the v3 codecs — one per domain,
 * each targeting its own concrete `public.eql_v3_*` native type. */
export const cipherstashV3StorageRows: ReadonlyArray<{
  readonly typeId: string
  readonly familyId: 'sql'
  readonly targetId: 'postgres'
  readonly nativeType: string
}> = [...V3_DOMAIN_META_BY_CODEC_ID.entries()].map(([codecId, meta]) => ({
  typeId: codecId,
  familyId: 'sql',
  targetId: 'postgres',
  nativeType: meta.nativeType,
}))
