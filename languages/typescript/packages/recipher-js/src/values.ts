/**
 * The values the SDK encrypts, and the types they open as.
 *
 * A value's type picks how it is encrypted, by vitaminc's mapping for
 * JavaScript:
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
 * Integers are a `bigint`: a `number` is a float, and `5` does not equal
 * the integer `5n`. A plain object is refused: wrap it in `json(..)`.
 *
 * The wrapper classes (`VcDate`, `VcTimestamp`, `VcDecimal`, `VcUuid`) and
 * `json` are the native build's. Without a build, stand-ins take their
 * place: each constructs as the class does, and `encrypt` then resolves to
 * the `Err` that says why the build did not load.
 */
import { binding } from './binding'

declare const wrapper: unique symbol

/** A calendar date, such as `new VcDate('2026-11-23')`. vitaminc's class. */
export interface VcDate {
  /** The date as `YYYY-MM-DD`. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcDate'
}

/** A UTC instant to the nanosecond. vitaminc's class. */
export interface VcTimestamp {
  /** The instant as RFC 3339 text with nanoseconds. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcTimestamp'
}

/** A decimal with its scale, such as `new VcDecimal('1.50')`. vitaminc's class. */
export interface VcDecimal {
  /** The decimal as text, with its scale. */
  readonly value: string
  toJSON(): string
  readonly [wrapper]: 'VcDecimal'
}

/**
 * A UUID. vitaminc's class. The engine's value model does not hold a UUID
 * yet, so encrypting one is an `Err` of kind `value` (code
 * `recipher::uuid`), and it is not a `Scalar`.
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
 * The class the native build defines, or a stand-in that holds its text, is
 * frozen, and serialises as vitaminc's does.
 */
function wrapperClass<W>(name: WrapperName): WrapperConstructor<W> {
  if (binding.isOk()) {
    // The build exports each class under its name (`crate/src/lib.rs`);
    // napi-rs does not declare them, so they are typed here.
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

/** A value that is one scalar. */
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
 * `bigint`, within the 64-bit range (`-(2n ** 63n)` to `2n ** 64n - 1n`);
 * on encrypt, a whole `number` between 2^53 and 2^64 from zero is refused,
 * because an integer was likely meant.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue }

/** A JSON document as it opens. */
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
   * Marks a `Json`, so no other object is one. Nothing at run time holds
   * it: a `Json` is the native build's class.
   */
  readonly [document]: true
}

/** A JSON document, to encrypt as one ciphertext. */
export type JsonFunction = (document: JsonValue) => Json

/**
 * A JSON document, to encrypt as one ciphertext. The document is read now,
 * so a later change to the object does not change what is encrypted. Never
 * throws: a document that cannot be encrypted (bytes or a `Date` in it,
 * nesting deeper than 127 levels) is an `Err` from `encrypt`.
 */
export const json: JsonFunction = binding.isOk()
  ? nativeJson(binding.value.json)
  : standInJson

/** The native `json`, which returns its `Json` class, as `Json` types it. */
function nativeJson(native: (document: unknown) => unknown): JsonFunction {
  // biome-ignore lint/plugin: the native class carries no TypeScript brand; `Json` describes it.
  return native as unknown as JsonFunction
}

/** The stand-in for `json` when the native build did not load. */
function standInJson(): Json {
  // biome-ignore lint/plugin: a stand-in `Json`, which `encrypt` refuses with the load error.
  return Object.freeze({ toString: () => 'Json(***)' }) as unknown as Json
}

/** A value `encrypt` takes. */
export type Value = Scalar | Json

/** The type a value of type `V` decrypts as. */
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

/** Any scalar a stored ciphertext can open as. */
export type OpenedScalar = Opened<Scalar>
