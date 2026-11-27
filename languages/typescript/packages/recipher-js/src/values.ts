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
 * | `VcUuid` | a UUID | `VcUuid` |
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
import type * as Native from '../native'
import { type Binding, binding } from './binding'
import type {
  VcDate as VcDateValue,
  VcDecimal as VcDecimalValue,
  VcTimestamp as VcTimestampValue,
  VcUuid as VcUuidValue,
} from './value-types'

export type {
  JsonValue,
  Opened,
  OpenedJson,
  OpenedScalar,
  Scalar,
} from './value-types'

/** A value that `encrypt` takes: one scalar, or a `Json` document. */
export type Value = Native.Value

/** A calendar date, such as `new VcDate('2026-11-23')`. The class comes from vitaminc. */
export type VcDate = VcDateValue
/** A UTC instant, to the nanosecond. The class comes from vitaminc. */
export type VcTimestamp = VcTimestampValue
/** A decimal with its scale, such as `new VcDecimal('1.50')`. The class comes from vitaminc. */
export type VcDecimal = VcDecimalValue
/**
 * A universally unique identifier (UUID), such as
 * `new VcUuid('123e4567-e89b-12d3-a456-426614174000')`. The class comes from
 * vitaminc.
 *
 * The text is hyphenated hex, in either case. Encrypting other text, such
 * as text in braces, of the wrong length, or with a digit that is not hex,
 * is an `Err` with the code `ERR_INVALID_UUID`. A decrypted `VcUuid` holds
 * lowercase hyphenated hex, whatever case it was built with.
 */
export type VcUuid = VcUuidValue

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

/**
 * A JSON document to encrypt as one ciphertext, as its JSON text. Make one
 * with `json(..)`. `toString()` and Node's `inspect` hide the document.
 *
 * The type is the native addon's `Json` class.
 */
export type Json = Native.Json

/** The type of `json`, which makes a JSON document to encrypt as one ciphertext. */
export type JsonFunction = Binding['json']

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
  ? binding.value.json
  : standInJson

/** The stand-in for `json` when the native addon did not load. */
function standInJson(): Json {
  // biome-ignore lint/plugin: a stand-in `Json`, which `encrypt` refuses with the load error.
  return Object.freeze({ toString: () => 'Json(***)' }) as unknown as Json
}
