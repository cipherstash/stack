/**
 * v3 runtime codecs — one `RuntimeParameterizedCodecDescriptor` per
 * catalog domain, derived from `V3_DOMAIN_META_BY_CODEC_ID` (never
 * hand-listed). Parallel to the v2 `../execution/codec-runtime.ts` +
 * `../execution/parameterized.ts` pair, with three deliberate
 * differences:
 *
 *   - **Wire**: plain JSONB (`./wire-v3`), never the v2
 *     `eql_v2_encrypted` composite literal. This module MUST NOT import
 *     the v2 codec/wire (`encodeEqlV2EncryptedWire`), the v2
 *     codec-runtime, or the v2 bulk-encrypt middleware.
 *   - **Native type**: each descriptor targets its concrete
 *     `public.eql_v3_*` domain (v2's six codecs all share one
 *     `eql_v2_encrypted` composite type).
 *   - **Traits**: derived per-domain from the catalog's query
 *     capabilities via `v3TraitsForCapabilities` — the capability set is
 *     intrinsic to the domain, not a per-column authoring option.
 *
 * Params shape matches the static `typeParams` block that v3 authoring
 * emits (`contract-authoring.ts`): `{ castAs, capabilities }`. The codec
 * runtime is stateless across params (encode reads ciphertext from the
 * handle; decode constructs the per-castAs envelope), so the factory
 * returns one shared codec per domain, mirroring v2 / pgvector.
 */

import type { JsonValue } from '@prisma-next/contract/types'
import {
  type AnyCodecDescriptor,
  CodecImpl,
  type CodecInstanceContext,
  type CodecTrait,
} from '@prisma-next/framework-components/codec'
import { runtimeError } from '@prisma-next/framework-components/runtime'
import type { SqlCodecCallContext } from '@prisma-next/sql-relational-core/ast'
import type { RuntimeParameterizedCodecDescriptor } from '@prisma-next/sql-runtime'
import { type as arktype } from 'arktype'
import type { EncryptedEnvelopeBase } from '../execution/envelope-base'
import { EncryptedBigInt } from '../execution/envelope-bigint'
import { EncryptedBoolean } from '../execution/envelope-boolean'
import { EncryptedDate } from '../execution/envelope-date'
import { EncryptedJson } from '../execution/envelope-json'
import { EncryptedString } from '../execution/envelope-string'
import { isBulkEncryptMiddlewareRegistered } from '../execution/middleware-registry'
import type { CipherstashSdk } from '../execution/sdk'
import {
  isCipherstashV3CodecId,
  v3TraitsForCapabilities,
} from '../extension-metadata/constants-v3'
import {
  envelopeTypeNameForCastAs,
  V3_DOMAIN_META_BY_CODEC_ID,
  type V3CastAs,
  type V3DomainMeta,
} from './catalog'
import { EncryptedNumber } from './envelope-number'
import { v3FromDriver, v3ToDriver } from './wire-v3'

/**
 * Per-domain params emitted by v3 authoring as a static `typeParams`
 * block. Purely descriptive — the runtime codec ignores them (the
 * capability set already determined the descriptor's traits at
 * derivation time).
 */
export interface CipherstashV3CodecParams {
  readonly castAs: string
  readonly capabilities: object
}

export const cipherstashV3ParamsSchema = arktype({
  castAs: 'string',
  capabilities: 'object',
})

type FromInternal = (args: {
  readonly ciphertext: unknown
  readonly table: string
  readonly column: string
  readonly sdk: CipherstashSdk
}) => EncryptedEnvelopeBase<unknown>

/**
 * Map a domain's `castAs` to its envelope `fromInternal` factory. Total
 * over `V3CastAs` — a new castAs kind fails to compile here. The
 * `date`/`timestamp` pair shares `EncryptedDate`; `json` reuses the
 * version-neutral `EncryptedJson` envelope class.
 */
function fromInternalForCastAs(castAs: V3CastAs): FromInternal {
  switch (castAs) {
    case 'string':
      return EncryptedString.fromInternal
    case 'number':
      return EncryptedNumber.fromInternal
    case 'bigint':
      return EncryptedBigInt.fromInternal
    case 'date':
    case 'timestamp':
      return EncryptedDate.fromInternal
    case 'boolean':
      return EncryptedBoolean.fromInternal
    case 'json':
      return EncryptedJson.fromInternal
  }
}

/**
 * `CodecDescriptor.traits` is typed against the framework's closed
 * `CodecTrait` union; the cipherstash traits live in the
 * extension-private `cipherstash:` namespace so trait-gated framework
 * built-ins (e.g. `eq` → SQL `=`) can never attach to encrypted
 * columns. Framework 0.14 treats traits as opaque strings at runtime;
 * the assertion is a type-level adapter only — same pattern (and full
 * rationale) as v2's `CIPHERSTASH_CODEC_TRAITS` in
 * `../extension-metadata/constants.ts`.
 */
function v3CodecTraits(meta: V3DomainMeta): readonly CodecTrait[] {
  return v3TraitsForCapabilities(meta.capabilities) as readonly CodecTrait[]
}

/**
 * The `(table, column)` routing key an EQL v3 payload carries in its own
 * `i` identifier (wire shape `{"t": "...", "c": "..."}`) — a required key
 * on every v3 domain, enforced by each `public.eql_v3_*` domain CHECK.
 *
 * This is the AUTHORITATIVE routing source, not a fallback for when the
 * query context is missing. ZeroKMS commits the cell's key to this
 * identifier, so a payload relocated to a different column cannot
 * decrypt — the identifier is what that guarantee is built on. Reading
 * routing from the value is therefore exactly as trustworthy as reading
 * it from the query that projected the value, and it is available on
 * paths where no column context exists at all: aggregates, computed
 * projections, and `decodeJson` (relation includes, whose JSON cells the
 * SQL runtime decodes without a `SqlColumnRef`).
 *
 * Returns `undefined` for a payload that carries no usable identifier —
 * a malformed or non-v3 document — so callers can fall back or raise a
 * diagnostic of their own.
 */
function routingKeyFromPayload(
  payload: unknown,
): { readonly table: string; readonly column: string } | undefined {
  if (typeof payload !== 'object' || payload === null) {
    return undefined
  }
  const identifier = (payload as { readonly i?: unknown }).i
  if (typeof identifier !== 'object' || identifier === null) {
    return undefined
  }
  const { t, c } = identifier as {
    readonly t?: unknown
    readonly c?: unknown
  }
  if (typeof t !== 'string' || typeof c !== 'string' || !t || !c) {
    return undefined
  }
  return { table: t, column: c }
}

export class CipherstashV3CellCodec<
  E extends EncryptedEnvelopeBase<unknown>,
> extends CodecImpl<string, readonly CodecTrait[], unknown, E> {
  readonly #sdk: CipherstashSdk
  readonly #fromInternal: FromInternal
  readonly #typeName: string
  // Memo: once this SDK is known-registered it can never become
  // unregistered (the registry is add-only), so the WeakSet lookup is
  // paid once per codec rather than once per encoded cell.
  #middlewareCheckPassed = false

  constructor(
    descriptor: AnyCodecDescriptor,
    sdk: CipherstashSdk,
    typeName: string,
    fromInternal: FromInternal,
  ) {
    super(descriptor)
    this.#sdk = sdk
    this.#typeName = typeName
    this.#fromInternal = fromInternal
  }

  async encode(value: E, _ctx: SqlCodecCallContext): Promise<unknown> {
    // Two-pass write path (same contract as v2, plain-JSONB wire): the
    // v3 bulk-encrypt middleware replaces the param with the JSONB text
    // before the driver reads it — pass a pre-serialised string through.
    // If we still hold an envelope, serialise its stamped ciphertext, or
    // return the envelope itself as the pre-encrypt sentinel.
    if (typeof value === 'string') {
      return value
    }
    if (value === null || value === undefined) {
      return value
    }
    const handle = value.expose()
    if (handle.ciphertext === undefined) {
      // Misconfig diagnostic (ported from the v2 codec's
      // `../execution/cell-codec-factory.ts`, deleted with the rest of
      // v2): an SDK-bound codec seeing a pre-encrypt envelope means no
      // `bulkEncryptMiddlewareV3(sdk)` was constructed against this same
      // SDK, so the two-pass write can never complete. Throw at the
      // codec boundary with a copy-pasteable wiring snippet rather than
      // letting the envelope reach the pg driver, where it surfaces as
      // an opaque serialise error.
      if (!this.#middlewareCheckPassed) {
        if (!isBulkEncryptMiddlewareRegistered(this.#sdk)) {
          throw runtimeError(
            'RUNTIME.ENCODE_FAILED',
            `cipherstash ${this.descriptor.codecId}: encrypted column value has not been encrypted, ` +
              'and no `bulkEncryptMiddlewareV3(sdk)` has been registered with this SDK. ' +
              'Wire it up alongside the extension descriptor:\n\n' +
              '  postgres<Contract>({\n' +
              '    contractJson,\n' +
              '    extensions: [createCipherstashV3RuntimeDescriptor({ sdk })],\n' +
              '    middleware:  [bulkEncryptMiddlewareV3(sdk)],\n' +
              '  });\n\n' +
              'Both must close over the SAME `sdk` reference. See the @cipherstash/prisma-next README for the full wiring example.',
            {
              codecId: this.descriptor.codecId,
              reason: 'cipherstash-bulk-encrypt-middleware-not-registered',
              envelopeRouting: { table: handle.table, column: handle.column },
            },
          )
        }
        this.#middlewareCheckPassed = true
      }
      return value
    }
    return v3ToDriver(handle.ciphertext)
  }

  async decode(wire: unknown, ctx: SqlCodecCallContext): Promise<E> {
    const payload = v3FromDriver(wire as string | object | null | undefined)
    // The payload's own `i` identifier is authoritative (see
    // `routingKeyFromPayload`). `ctx.column` remains as a fallback for a
    // document carrying no usable identifier — a NULL cell, or a
    // non-v3/malformed value the domain CHECK would have rejected on the
    // way in — so a well-routed query still decodes such a cell exactly
    // as it did before.
    const routing =
      routingKeyFromPayload(payload) ??
      (ctx.column
        ? { table: ctx.column.table, column: ctx.column.name }
        : undefined)
    if (!routing) {
      throw runtimeError(
        'RUNTIME.DECODE_FAILED',
        `cipherstash ${this.descriptor.codecId}: decode could not determine the (table, column) routing key. ` +
          'The cell carries no EQL `i` identifier (so it is not a well-formed v3 payload), and the SQL runtime ' +
          'supplied no projected-column context — the cell came from an aggregate, computed expression, or other ' +
          'unrouted source. cipherstash codecs need a stable routing key for envelope construction and bulk-decrypt ' +
          'grouping; project the underlying encrypted column directly instead of through an aggregate.',
        {
          codecId: this.descriptor.codecId,
          reason: 'cipherstash-v3-decode-routing-key-unresolvable',
        },
      )
    }
    // The per-domain `fromInternal` returns the base type; each codec is
    // constructed with the factory matching its domain's castAs, so the
    // narrow to `E` holds by construction.
    return this.#fromInternal({
      ciphertext: payload,
      table: routing.table,
      column: routing.column,
      sdk: this.#sdk,
    }) as E
  }

  encodeJson(_value: E): JsonValue {
    const marker = `$${this.#typeName.charAt(0).toLowerCase()}${this.#typeName.slice(1)}`
    return { [marker]: '<opaque>' } as JsonValue
  }

  /**
   * Decode a v3 payload embedded in a database-produced JSON value —
   * the path the SQL runtime takes for a relation `include()`, where a
   * cell arrives inside a `json_agg` / `json_build_object` document with
   * no `SqlColumnRef` attached.
   *
   * Routing comes from the payload's own `i` identifier, which is all
   * this path needs: the codec instance already closes over the SDK, so
   * the envelope it builds is indistinguishable from one built by
   * `decode`, and `decryptAll` batches it into the same
   * `(sdk, table, column)` group.
   *
   * Note this is NOT the inverse of `encodeJson`, which deliberately
   * renders the opaque `$encrypted*` marker so a serialised envelope
   * never carries ciphertext. Round-tripping an `encodeJson` marker back
   * through here is not supported and raises below — the two methods
   * serve the write and read directions of different planes.
   */
  decodeJson(json: JsonValue): E {
    const routing = routingKeyFromPayload(json)
    if (!routing) {
      throw runtimeError(
        'RUNTIME.DECODE_FAILED',
        `cipherstash ${this.descriptor.codecId}: decodeJson requires a well-formed EQL v3 payload carrying its ` +
          '`i` identifier (`{"t": "<table>", "c": "<column>"}`), which is what supplies the routing key on the ' +
          'JSON plane. The value received carries no such identifier — an opaque `$encrypted*` marker produced by ' +
          '`encodeJson` will not round-trip here, and neither will a non-v3 document.',
        {
          codecId: this.descriptor.codecId,
          reason: 'cipherstash-v3-decode-json-identifier-missing',
        },
      )
    }
    return this.#fromInternal({
      ciphertext: json,
      table: routing.table,
      column: routing.column,
      sdk: this.#sdk,
    }) as E
  }
}

/**
 * Auxiliary descriptor for the `CodecImpl` base class — carries truthful
 * metadata (codecId, traits, targetTypes, meta, renderOutputType) for
 * readers that proxy through `codec.descriptor`, with a throwing
 * `factory` stub: production resolution goes through the parameterized
 * descriptors below, never `codec.descriptor.factory`. Same shape (and
 * circularity rationale) as v2's `makeAuxiliaryDescriptor` in
 * `../execution/cell-codec-factory.ts`.
 */
function makeV3AuxiliaryDescriptor(
  codecId: string,
  meta: V3DomainMeta,
  typeName: string,
): AnyCodecDescriptor {
  return {
    codecId,
    traits: v3CodecTraits(meta),
    targetTypes: [meta.nativeType],
    meta: { db: { sql: { postgres: { nativeType: meta.nativeType } } } },
    paramsSchema: cipherstashV3ParamsSchema,
    isParameterized: true,
    renderOutputType: () => typeName,
    factory: () => () => {
      throw new Error(
        'cipherstash v3 codec: auxiliary descriptor factory was invoked. ' +
          'This is a programming error — v3 codecs are resolved through the ' +
          'parameterized descriptors returned by `createV3CodecDescriptors(sdk)`, ' +
          'not through `codec.descriptor.factory`.',
      )
    },
  }
}

function makeV3Descriptor(
  sdk: CipherstashSdk,
  codecId: string,
  meta: V3DomainMeta,
): RuntimeParameterizedCodecDescriptor<CipherstashV3CodecParams> {
  const typeName = envelopeTypeNameForCastAs(meta.castAs)
  const codec = new CipherstashV3CellCodec<EncryptedEnvelopeBase<unknown>>(
    makeV3AuxiliaryDescriptor(codecId, meta, typeName),
    sdk,
    typeName,
    fromInternalForCastAs(meta.castAs),
  )
  return {
    codecId,
    traits: v3CodecTraits(meta),
    targetTypes: [meta.nativeType],
    meta: { db: { sql: { postgres: { nativeType: meta.nativeType } } } },
    paramsSchema: cipherstashV3ParamsSchema,
    isParameterized: true as const,
    renderOutputType: (_params: CipherstashV3CodecParams) => typeName,
    factory:
      (_params: CipherstashV3CodecParams) => (_ctx: CodecInstanceContext) =>
        codec,
  }
}

/**
 * One runtime descriptor per catalog domain (all 40, including the
 * authoring-unexposed `*_ord_ore` variants — the codec layer must decode
 * whatever the catalog can name), closed over `sdk` so multi-tenant
 * deployments can compose multiple cipherstash extensions side-by-side
 * without cross-talk.
 */
export function createV3CodecDescriptors(
  sdk: CipherstashSdk,
): ReadonlyArray<
  RuntimeParameterizedCodecDescriptor<CipherstashV3CodecParams>
> {
  return [...V3_DOMAIN_META_BY_CODEC_ID.entries()].map(([codecId, meta]) => {
    // The catalog and the pinned codec-id union are compile-time-locked
    // to each other (see constants-v3.ts); a mismatch here means the
    // derivation itself drifted — fail loudly.
    if (!isCipherstashV3CodecId(codecId)) {
      throw new Error(
        `cipherstash v3 codec: catalog produced unpinned codec id "${codecId}" — update CIPHERSTASH_V3_CODEC_IDS.`,
      )
    }
    return makeV3Descriptor(sdk, codecId, meta)
  })
}
