/**
 * The types of the values the SDK encrypts, and of what they decrypt to.
 *
 * This module contains types only, and imports nothing. The addon's
 * generated declarations (`native.d.ts`) name these types in their
 * signatures. If a module here loaded the addon, the declarations would
 * import themselves.
 */

declare const wrapper: unique symbol

/** A calendar date, such as `new RcDate('2026-11-23')`. */
export interface RcDate {
  /** The date as `YYYY-MM-DD`. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'RcDate'
}

/** A UTC instant, to the nanosecond. */
export interface RcTimestamp {
  /** The instant as RFC 3339 text, with nanoseconds. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'RcTimestamp'
}

/** A decimal with its scale, such as `new RcDecimal('1.50')`. */
export interface RcDecimal {
  /** The decimal as text, with its scale. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'RcDecimal'
}

/**
 * A universally unique identifier (UUID).
 * This version of the SDK does not encrypt a UUID yet. Encrypting an `RcUuid`
 * is an `Err` with the code `recipher_js::uuid`. `RcUuid` is not a `Scalar`.
 */
export interface RcUuid {
  /** The UUID as hyphenated hex. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'RcUuid'
}

/** A value that is one scalar: a single value, not a JSON document. */
export type Scalar =
  | string
  | boolean
  | number
  | bigint
  | Uint8Array
  | Date
  | RcTimestamp
  | RcDate
  | RcDecimal
  | null

/**
 * A JSON value.
 *
 * The safe range of a `number` is 2^53 - 1 either side of zero. Write an
 * integer outside the safe range as a `bigint`. The `bigint` must be in the
 * 64-bit range, from `-(2n ** 63n)` to `2n ** 64n - 1n`.
 *
 * `encrypt` stores a whole `number` in the safe range as an integer, and any
 * other `number` as a float. `encrypt` refuses a whole `number` from 2^53 up
 * to 2^64, either side of zero. A `number` that large may not keep the
 * digits that were written. `encrypt` also refuses `NaN` and the infinities.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue }

/**
 * A JSON document as it decrypts. An integer is a `number` when it is in the
 * safe range of a `number`, and a `bigint` otherwise. The safe range is 2^53
 * - 1 either side of zero. A decrypted object lists its members sorted by
 * key.
 */
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
 * The marker of a `Json`. `Json` is the native addon's class for a JSON
 * document. The marker stops any other object type-checking as a `Json`. The
 * marker never exists at run time.
 */
export interface JsonMarker {
  readonly [document]: true
}

/** The type that a value of type `V` decrypts to. */
export type Opened<V> = V extends string
  ? string
  : V extends boolean
    ? boolean
    : V extends number
      ? number
      : V extends bigint
        ? bigint
        : V extends Uint8Array
          ? Uint8Array
          : V extends Date
            ? Date
            : V extends RcTimestamp
              ? Date | RcTimestamp
              : V extends RcDate
                ? RcDate
                : V extends RcDecimal
                  ? RcDecimal
                  : V extends null
                    ? null
                    : V extends JsonMarker
                      ? OpenedJson
                      : never

/** Any scalar type that a stored ciphertext can decrypt to. */
export type OpenedScalar = Opened<Scalar>
