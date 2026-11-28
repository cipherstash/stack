/**
 * The values the SDK encrypts, and the types they decrypt to.
 *
 * A value's type decides how it is encrypted. The value bridge defines the
 * mapping. The value bridge is the part of the native addon that converts
 * JavaScript values.
 *
 * | Value | Encrypted as | Decrypts as |
 * |---|---|---|
 * | `string` | text | `string` |
 * | `boolean` | a boolean | `boolean` |
 * | `number` | a 64-bit float | `number` |
 * | `bigint` | an integer, at the narrowest width that holds it | `bigint` |
 * | `Uint8Array`, `Buffer` | bytes | `Uint8Array` |
 * | `Date` | a timestamp | `Date` |
 * | `RcTimestamp` | a timestamp, in nanoseconds | `Date` when it is whole milliseconds, else `RcTimestamp` |
 * | `RcDate` | a calendar date | `RcDate` |
 * | `RcDecimal` | a decimal, with its scale | `RcDecimal` |
 * | `null` | null | `null` |
 * | `json(value)` | a JSON document, as its text | the document |
 *
 * Integers are a `bigint`. A `number` is a float. The `number` `5` does not
 * equal the integer `5n`.
 *
 * A plain object is refused, because an object has no single stored form.
 * `json(..)` encrypts it as a JSON document. `opaque(..)` will encrypt a
 * whole object in the engine's own format, and is not built yet.
 *
 * The wrapper classes (`RcDate`, `RcTimestamp`, `RcDecimal`, and `RcUuid`)
 * and `json` come from the native addon. When the addon did not load,
 * stand-ins take their place. Each stand-in constructs as the class does.
 * `encrypt` then resolves to the `Err` that says why the addon did not load.
 *
 * A wrapper class's constructor takes a string. It throws a `TypeError` for
 * any other argument. The text is checked when the value is encrypted.
 */
import type * as Native from '../native'
import { type Binding, binding } from './binding'
import type * as Types from './value-types'

export type {
  JsonValue,
  Opened,
  OpenedJson,
  OpenedScalar,
  Scalar,
  Value,
} from './value-types'

/** The constructor of a wrapper class. */
export interface WrapperConstructor<W> {
  new (text: string): W
  readonly prototype: W
}

type WrapperName = 'RcDate' | 'RcTimestamp' | 'RcDecimal' | 'RcUuid'

/**
 * A stand-in for the wrapper class `name`, for when the native addon did
 * not load. It constructs as the addon's class does: it takes a string and
 * throws a `TypeError` for anything else, keeps the text in a read-only
 * `value`, is frozen, and gives the same text to `String`, `JSON.stringify`
 * and Node's `inspect`.
 */
export function standInWrapper<W>(name: WrapperName): WrapperConstructor<W> {
  const StandIn = class {
    readonly value: string
    constructor(text: string) {
      if (typeof text !== 'string') {
        throw new TypeError(`${name} takes a string`)
      }
      this.value = text
      Object.freeze(this)
    }
    toJSON(): string {
      return this.value
    }
    toString(): string {
      return this.value
    }
    [Symbol.for('nodejs.util.inspect.custom')](): string {
      return `${name}(${this.value})`
    }
  }
  Object.defineProperty(StandIn, 'name', { value: name })
  Object.freeze(StandIn.prototype)
  // biome-ignore lint/plugin: a stand-in for the class, which constructs as it does.
  return Object.freeze(StandIn) as unknown as WrapperConstructor<W>
}

/**
 * The class that the native addon defines. When the addon did not load, a
 * stand-in class instead.
 */
function wrapperClass<W>(name: WrapperName): WrapperConstructor<W> {
  if (binding.isOk()) {
    // The addon exports each class under its name (`crate/src/lib.rs`).
    // napi-rs does not declare these classes, so this code gives them types.
    return Reflect.get(binding.value, name) as WrapperConstructor<W>
  }
  return standInWrapper(name)
}

// A class is a constant and a type of one name. `./value-types` declares the
// types, because the addon's declarations name them, and a module cannot
// export a type from another module and a constant under the same name. So
// each constant here has its type beside it.

/** A calendar date, such as `new RcDate('2026-11-23')`. */
export const RcDate: WrapperConstructor<RcDate> = wrapperClass('RcDate')
export type RcDate = Types.RcDate

/**
 * A UTC instant, to the nanosecond, such as
 * `new RcTimestamp('2026-11-23T01:02:03.000000001Z')`.
 */
export const RcTimestamp: WrapperConstructor<RcTimestamp> =
  wrapperClass('RcTimestamp')
export type RcTimestamp = Types.RcTimestamp

/** A decimal with its scale, such as `new RcDecimal('1.50')`. */
export const RcDecimal: WrapperConstructor<RcDecimal> =
  wrapperClass('RcDecimal')
export type RcDecimal = Types.RcDecimal

/**
 * A universally unique identifier (UUID). The engine has no plaintext type
 * for a UUID yet. Encrypting an `RcUuid` is an `Err` with the code
 * `recipher_js::uuid`. `RcUuid` is not a `Scalar`.
 */
export const RcUuid: WrapperConstructor<RcUuid> = wrapperClass('RcUuid')
export type RcUuid = Types.RcUuid

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
