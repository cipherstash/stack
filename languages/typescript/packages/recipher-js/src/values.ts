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
import type * as Native from '../native'
import type * as Bridge from '../value-napi/src/wrappers'
import { type Binding, binding } from './binding'

export type { WrapperConstructor } from '../value-napi/src/wrappers'
export type {
  JsonValue,
  Opened,
  OpenedJson,
  OpenedScalar,
  Scalar,
  Value,
} from './value-types'

// Each class is a value and a type of the same name. TypeScript cannot
// re-export a type under a name this module also gives a value, so each
// type is named again here.
/** A calendar date, such as `new VcDate('2026-11-23')`. */
export type VcDate = Bridge.VcDate
/** A UTC instant, to the nanosecond. */
export type VcTimestamp = Bridge.VcTimestamp
/** A decimal with its scale, such as `new VcDecimal('1.50')`. */
export type VcDecimal = Bridge.VcDecimal
/** A universally unique identifier (UUID). `encrypt` refuses one. */
export type VcUuid = Bridge.VcUuid

/**
 * The class that the native addon exports. When the addon did not load, a
 * stand-in class instead. The stand-in keeps its text, is frozen, and
 * serialises to JSON as the class does.
 */
function wrapperClass<N extends keyof Bridge.WrapperClasses>(
  name: N,
): Binding[N] {
  if (binding.isOk()) {
    return binding.value[name]
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
  return Object.freeze(StandIn) as unknown as Binding[N]
}

/** A calendar date. */
export const VcDate = wrapperClass('VcDate')
/** A UTC instant to the nanosecond. */
export const VcTimestamp = wrapperClass('VcTimestamp')
/** A decimal with its scale. */
export const VcDecimal = wrapperClass('VcDecimal')
/** A UUID. */
export const VcUuid = wrapperClass('VcUuid')

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
