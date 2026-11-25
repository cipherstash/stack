/**
 * The types of the values the SDK encrypts, and of what they decrypt to.
 *
 * The value bridge declares how a scalar maps to JavaScript and back
 * (`value-napi/src/values.d.ts`). This module adds what the SDK decides:
 * which scalars `encrypt` takes, and JSON documents, which the addon
 * converts itself.
 *
 * This module holds types only, and imports only types. The addon's
 * generated declarations (`native.d.ts`) name these types in their
 * signatures, so a module here that loaded the addon would make the
 * declarations import themselves.
 */
import type {
  Opened as BridgeOpened,
  Scalar as BridgeScalar,
} from '../value-napi/src/values'
import type { VcUuid } from '../value-napi/src/wrappers'

/**
 * A value that is one scalar: a single value, not a JSON document.
 *
 * The bridge also reads `undefined` and a `VcUuid`, and `encrypt` refuses
 * both. The engine has no plaintext type for a UUID yet: encrypting a
 * `VcUuid` is an `Err` with the code `recipher_js::uuid`.
 */
export type Scalar = Exclude<BridgeScalar, undefined | VcUuid>

/**
 * A JSON value. An integer outside the safe range of a `number` is a
 * `bigint`, within the 64-bit range (`-(2n ** 63n)` to `2n ** 64n - 1n`).
 *
 * `encrypt` refuses a whole `number` whose absolute value is at least 2^53
 * but less than 2^64. An integer was likely meant.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue }

/** A JSON document as it decrypts. */
export type OpenedJson =
  | null
  | boolean
  | number
  | bigint
  | string
  | OpenedJson[]
  | { [key: string]: OpenedJson }

declare const document: unique symbol

/**
 * What marks a `Json`, the native addon's class for a JSON document, so
 * that no other object type-checks as one. The marker never exists at run
 * time.
 */
export interface JsonMarker {
  readonly [document]: true
}

/** A value that `encrypt` takes. */
export type Value = Scalar | JsonMarker

/** The type that a value of type `V` decrypts to. */
export type Opened<V> = V extends JsonMarker ? OpenedJson : BridgeOpened<V>

/** Any scalar type that a stored ciphertext can decrypt to. */
export type OpenedScalar = Opened<Scalar>
