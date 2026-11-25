/**
 * The types of the values the SDK encrypts, and of what they decrypt to.
 *
 * This module holds types only, and imports nothing. The addon's generated
 * declarations (`native.d.ts`) name these types in their signatures, so a
 * module here that loaded the addon would make the declarations import
 * themselves.
 */

declare const wrapper: unique symbol

/** A calendar date, such as `new VcDate('2026-11-23')`. The class comes from vitaminc. */
export interface VcDate {
  /** The date as `YYYY-MM-DD`. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcDate'
}

/** A UTC instant, to the nanosecond. The class comes from vitaminc. */
export interface VcTimestamp {
  /** The instant as RFC 3339 text, with nanoseconds. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcTimestamp'
}

/** A decimal with its scale, such as `new VcDecimal('1.50')`. The class comes from vitaminc. */
export interface VcDecimal {
  /** The decimal as text, with its scale. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcDecimal'
}

/**
 * A universally unique identifier (UUID). The class comes from vitaminc.
 * The engine has no plaintext type for a UUID yet. Encrypting a `VcUuid` is
 * an `Err` with the code `recipher_js::uuid`. `VcUuid` is not a `Scalar`.
 */
export interface VcUuid {
  /** The UUID as hyphenated hex. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcUuid'
}

/** A value that is one scalar: a single value, not a JSON document. */
export type Scalar =
  | string
  | boolean
  | number
  | bigint
  | Uint8Array
  | Date
  | VcTimestamp
  | VcDate
  | VcDecimal
  | null

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
            : V extends VcTimestamp
              ? Date | VcTimestamp
              : V extends VcDate
                ? VcDate
                : V extends VcDecimal
                  ? VcDecimal
                  : V extends null
                    ? null
                    : V extends JsonMarker
                      ? OpenedJson
                      : never

/** Any scalar type that a stored ciphertext can decrypt to. */
export type OpenedScalar = Opened<Scalar>
