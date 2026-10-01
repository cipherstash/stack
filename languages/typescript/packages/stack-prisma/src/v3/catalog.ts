/**
 * v3 domain catalog — derived (never hand-maintained) from the imported
 * `DOMAIN_REGISTRY`. For each bare domain name we probe its factory and read
 * `getEqlType()` (the `public.*` native type), `getQueryCapabilities()`, and
 * `build()` (`cast_as` + `indexes`) off the instance. Codec id is
 * `cipherstash/eql-v3/${bareDomain}@1` where `bareDomain` is the registry key
 * VERBATIM (only the `public.` schema qualifier is stripped). GA domains are
 * `eql_v3_*`-prefixed, so ids read `cipherstash/eql-v3/eql_v3_text_search@1` —
 * deliberately: the id is a mechanical bijection with the registry key, never a
 * prettified transform decode would have to invert. The `eql-v3` token is a
 * logical version tag, NOT the operator schema.
 */
// The registry is adapter-seam surface (`adapter-kit`), consumed here the same
// way the Drizzle and Supabase adapters consume it; the public `eql/v3` entry
// stays end-user authoring API only (see stack's `adapter-kit.ts` header).
import {
  type AnyEncryptedV3Column,
  DOMAIN_REGISTRY,
} from '@cipherstash/stack/adapter-kit'
import type { QueryCapabilities } from '@cipherstash/stack/eql/v3'

type V3ColumnFactory = (name: string) => AnyEncryptedV3Column

export type V3CastAs =
  | 'string'
  | 'number'
  | 'bigint'
  | 'boolean'
  | 'date'
  | 'timestamp'
  | 'json'

export interface V3DomainMeta {
  readonly nativeType: `public.${string}`
  readonly bareDomain: string
  readonly castAs: V3CastAs
  readonly capabilities: QueryCapabilities
  readonly indexes: Readonly<Record<string, unknown>>
}

export function toV3CodecId(bareDomain: string): string {
  return `cipherstash/eql-v3/${bareDomain}@1`
}

const PROBE = '__probe__'

function metaFor(bareDomain: string, factory: V3ColumnFactory): V3DomainMeta {
  const column = factory(PROBE)
  const built = column.build()
  return {
    nativeType: column.getEqlType(),
    bareDomain,
    castAs: built.cast_as as V3CastAs,
    capabilities: column.getQueryCapabilities(),
    indexes: built.indexes,
  }
}

const registryEntries: ReadonlyArray<readonly [string, V3ColumnFactory]> =
  Object.entries(DOMAIN_REGISTRY)

const metaEntries: Array<readonly [string, V3DomainMeta]> = registryEntries.map(
  ([bareDomain, factory]) =>
    [toV3CodecId(bareDomain), metaFor(bareDomain, factory)] as const,
)

export const V3_DOMAIN_META_BY_CODEC_ID: ReadonlyMap<string, V3DomainMeta> =
  new Map(metaEntries)

export const V3_CODEC_IDS: readonly string[] = metaEntries.map(([id]) => id)

export const V3_FACTORY_BY_NATIVE_TYPE: ReadonlyMap<
  string,
  (name: string) => AnyEncryptedV3Column
> = new Map(
  registryEntries.map(
    ([, factory]) => [factory(PROBE).getEqlType(), factory] as const,
  ),
)

export function isOrdOreDomain(bareDomain: string): boolean {
  return bareDomain.endsWith('_ord_ore')
}

export const EXPOSED_DOMAIN_ENTRIES: ReadonlyArray<
  readonly [string, V3DomainMeta]
> = metaEntries.filter(([, meta]) => !isOrdOreDomain(meta.bareDomain))

export function envelopeTypeNameForCastAs(
  castAs: V3CastAs,
):
  | 'EncryptedString'
  | 'EncryptedNumber'
  | 'EncryptedBigInt'
  | 'EncryptedDate'
  | 'EncryptedBoolean'
  | 'EncryptedJson' {
  switch (castAs) {
    case 'string':
      return 'EncryptedString'
    case 'number':
      return 'EncryptedNumber'
    case 'bigint':
      return 'EncryptedBigInt'
    case 'date':
    case 'timestamp':
      return 'EncryptedDate'
    case 'boolean':
      return 'EncryptedBoolean'
    case 'json':
      return 'EncryptedJson'
  }
}
