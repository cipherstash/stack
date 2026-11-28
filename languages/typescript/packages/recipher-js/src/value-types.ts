/**
 * The types of the values the SDK encrypts, and of what they decrypt to.
 *
 * This module holds types only, and imports nothing. The addon's generated
 * declarations (`native.d.ts`) name these types in their signatures, so a
 * module here that loaded the addon would make the declarations import
 * themselves.
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
 * The engine has no plaintext type for a UUID yet. Encrypting an `RcUuid` is
 * an `Err` with the code `recipher_js::uuid`. `RcUuid` is not a `Scalar`.
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
 * A JSON value. An integer outside the safe range of a `number` is a
 * `bigint`, within the 64-bit range (`-(2n ** 63n)` to `2n ** 64n - 1n`).
 * The safe range is 2^53 - 1 either side of zero.
 *
 * A whole `number` in the safe range is stored as an integer, and any other
 * `number` as a float. `encrypt` refuses a whole `number` whose absolute
 * value is at least 2^53 but less than 2^64, because it may not keep the
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
 * A JSON document as it decrypts. An integer is a `number` when it is in
 * the safe range of a `number`, and a `bigint` otherwise. The members of an
 * object are sorted by key.
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
 * What marks a `Json`, the native addon's class for a JSON document, so
 * that no other object type-checks as one. The marker never exists at run
 * time.
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
