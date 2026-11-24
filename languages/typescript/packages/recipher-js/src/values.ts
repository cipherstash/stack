/**
 * The values the SDK encrypts, and the types they decrypt to.
 *
 * A value's type decides how it is encrypted. The mapping is vitaminc's
 * mapping for JavaScript. vitaminc is the CipherStash Rust library that the
 * engine's plaintext types come from.
 *
 * | Value | Encrypted as | Decrypts as |
 * |---|---|---|
 * | `string` | text | `string` |
 * | `boolean` | a boolean | `boolean` |
 * | `number` | a 64-bit float | `number` |
 * | `bigint` | an integer, at the narrowest width that holds it | `bigint` |
 * | `Uint8Array`, `Buffer` | bytes | `Uint8Array` |
 * | `Date` | a timestamp | `Date` |
 * | `VcTimestamp` | a timestamp, in nanoseconds | `Date` when it is whole milliseconds, else `VcTimestamp` |
 * | `VcDate` | a calendar date | `VcDate` |
 * | `VcDecimal` | a decimal, with its scale | `VcDecimal` |
 * | `null` | null | `null` |
 * | `json(value)` | a JSON document, as its text | the document |
 *
 * Integers are a `bigint`. A `number` is a float. The `number` `5` does not
 * equal the integer `5n`. A plain object is refused. Wrap it in `json(..)`.
 *
 * The wrapper classes (`VcDate`, `VcTimestamp`, `VcDecimal`, and `VcUuid`)
 * and `json` come from the native addon. When the addon did not load,
 * stand-ins take their place. Each stand-in constructs as the class does.
 * `encrypt` then resolves to the `Err` that says why the addon did not load.
 */
import { binding } from './binding'

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
 * an `Err` with the code `recipher::uuid`. `VcUuid` is not a `Scalar`.
 */
export interface VcUuid {
  /** The UUID as hyphenated hex. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcUuid'
}

/** The constructor of one of vitaminc's wrapper classes. */
export interface WrapperConstructor<W> {
  new (text: string): W
  readonly prototype: W
}

type WrapperName = 'VcDate' | 'VcTimestamp' | 'VcDecimal' | 'VcUuid'

/**
 * The class that the native addon defines. When the addon did not load, a
 * stand-in class instead. The stand-in keeps its text, is frozen, and
 * serialises to JSON as vitaminc's class does.
 */
function wrapperClass<W>(name: WrapperName): WrapperConstructor<W> {
  if (binding.isOk()) {
    // The addon exports each class under its name (`crate/src/lib.rs`).
    // napi-rs does not declare these classes, so this code gives them types.
    return Reflect.get(binding.value, name) as WrapperConstructor<W>
  }
  const StandIn = class {
    readonly value: string
    constructor(text: string) {
      this.value = String(text)
      Object.freeze(this)
    }
    toJSON(): string {
      return this.value
    }
  }
  Object.defineProperty(StandIn, 'name', { value: name })
  // biome-ignore lint/plugin: a stand-in for the class, which constructs as it does.
  return Object.freeze(StandIn) as unknown as WrapperConstructor<W>
}

/** A calendar date. */
export const VcDate: WrapperConstructor<VcDate> = wrapperClass('VcDate')
/** A UTC instant to the nanosecond. */
export const VcTimestamp: WrapperConstructor<VcTimestamp> =
  wrapperClass('VcTimestamp')
/** A decimal with its scale. */
export const VcDecimal: WrapperConstructor<VcDecimal> =
  wrapperClass('VcDecimal')
/** A UUID. */
export const VcUuid: WrapperConstructor<VcUuid> = wrapperClass('VcUuid')

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
 * A JSON document to encrypt as one ciphertext, as its JSON text. Make one
 * with `json(..)`. `toString()` and Node's `inspect` hide the document.
 */
export interface Json {
  toString(): string
  /**
   * Marks a `Json`, so that no other object type-checks as one. The marker
   * never exists at run time, because a `Json` is an instance of the native
   * addon's class.
   */
  readonly [document]: true
}

/** The type of `json`, which makes a JSON document to encrypt as one ciphertext. */
export type JsonFunction = (document: JsonValue) => Json

/**
 * A JSON document, to encrypt as one ciphertext. `json` reads the document
 * immediately, so a later change to the object does not change what is
 * encrypted.
 *
 * `json` never throws. A document that cannot be encrypted is an `Err` from
 * `encrypt`. Examples are a document that contains bytes or a `Date`, and a
 * document nested deeper than 127 levels.
 */
export const json: JsonFunction = binding.isOk()
  ? nativeJson(binding.value.json)
  : standInJson

/**
 * The native addon's `json` function, with the type `JsonFunction`. The
 * function returns an instance of the addon's `Json` class, which the `Json`
 * type describes.
 */
function nativeJson(native: (document: unknown) => unknown): JsonFunction {
  // biome-ignore lint/plugin: the native class carries no TypeScript brand; `Json` describes it.
  return native as unknown as JsonFunction
}

/** The stand-in for `json` when the native addon did not load. */
function standInJson(): Json {
  // biome-ignore lint/plugin: a stand-in `Json`, which `encrypt` refuses with the load error.
  return Object.freeze({ toString: () => 'Json(***)' }) as unknown as Json
}

/** A value that `encrypt` takes. */
export type Value = Scalar | Json

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
                    : V extends Json
                      ? OpenedJson
                      : never

/** Any scalar type that a stored ciphertext can decrypt to. */
export type OpenedScalar = Opened<Scalar>
