/**
 * The kinds of value, in the engine's words: what a stored ciphertext is
 * read back as (`Ciphertext.fromBytes(bytes, kinds.string)`).
 *
 * A kind is plain data, `{ name }`, with the engine's name for it. Its type
 * records the TypeScript type a value of the kind is: an integer kind's
 * values are a `bigint` at every width.
 */
import type { OpenedJson, VcDate, VcDecimal, VcTimestamp } from './values'

/** A kind: the type of a value, by the engine's name for it. */
export interface Kind<Name extends string = string, T = unknown> {
  /** The engine's name for the kind, such as `int32`. */
  readonly name: Name
  /** Records `T`, which nothing at run time holds. */
  readonly __value?: T
}

function kind<Name extends string, T>(name: Name): Kind<Name, T> {
  return Object.freeze({ name })
}

/** The type a value of kind `K` is. */
export type ValueOf<K> = K extends Kind<string, infer T> ? T : never

/**
 * The kinds, in the engine's words. An integer kind's values are a `bigint`
 * at every width. `json` is a JSON document, sealed as its JSON text.
 */
export const kinds = Object.freeze({
  string: kind<'string', string>('string'),
  boolean: kind<'bool', boolean>('bool'),
  int8: kind<'int8', bigint>('int8'),
  int16: kind<'int16', bigint>('int16'),
  int32: kind<'int32', bigint>('int32'),
  int64: kind<'int64', bigint>('int64'),
  int128: kind<'int128', bigint>('int128'),
  uint8: kind<'uint8', bigint>('uint8'),
  uint16: kind<'uint16', bigint>('uint16'),
  uint32: kind<'uint32', bigint>('uint32'),
  uint64: kind<'uint64', bigint>('uint64'),
  uint128: kind<'uint128', bigint>('uint128'),
  float32: kind<'float32', number>('float32'),
  float64: kind<'float64', number>('float64'),
  decimal: kind<'decimal', VcDecimal>('decimal'),
  date: kind<'date', VcDate>('date'),
  timestamp: kind<'timestamp', Date | VcTimestamp>('timestamp'),
  bytes: kind<'bytes', Uint8Array>('bytes'),
  json: kind<'json', OpenedJson>('json'),
})
