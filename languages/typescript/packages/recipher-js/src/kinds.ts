/**
 * Kinds: the types of value, by the engine's names for them. A kind says
 * what type a stored ciphertext decrypts to, as in
 * `Ciphertext.fromBytes(bytes, kinds.string)`.
 *
 * A kind is plain data, `{ name }`, that contains the engine's name for the
 * type. The kind's TypeScript type records the type of the kind's values.
 * An integer kind's values are a `bigint` at every width.
 */
import type { ScalarKinds } from '../value-napi/src/values'
import type { OpenedJson } from './value-types'

/** A kind: the type of a value, by the engine's name for it. */
export interface Kind<Name extends string = string, T = unknown> {
  /** The engine's name for the kind, such as `int32`. */
  readonly name: Name
  /** Carries `T` for the type checker. The property never exists at run time. */
  readonly __value?: T
}

/**
 * The type of each kind's values: the bridge's type for each scalar kind,
 * and a JSON document for `json`.
 */
type KindValues = ScalarKinds & { json: OpenedJson }

function kind<Name extends keyof KindValues>(
  name: Name,
): Kind<Name, KindValues[Name]> {
  return Object.freeze({ name })
}

/** The TypeScript type of a value of kind `K`. */
export type ValueOf<K> = K extends Kind<string, infer T> ? T : never

/**
 * The kinds, by the engine's names for them. An integer kind's values are a
 * `bigint` at every width. `json` is a JSON document, encrypted as its JSON
 * text.
 */
export const kinds = Object.freeze({
  string: kind('string'),
  boolean: kind('bool'),
  int8: kind('int8'),
  int16: kind('int16'),
  int32: kind('int32'),
  int64: kind('int64'),
  int128: kind('int128'),
  uint8: kind('uint8'),
  uint16: kind('uint16'),
  uint32: kind('uint32'),
  uint64: kind('uint64'),
  uint128: kind('uint128'),
  float32: kind('float32'),
  float64: kind('float64'),
  decimal: kind('decimal'),
  date: kind('date'),
  timestamp: kind('timestamp'),
  bytes: kind('bytes'),
  json: kind('json'),
})
