/**
 * The JavaScript values the bridge reads and builds, as TypeScript types.
 *
 * `JsRef` reads a JavaScript value as a scalar. `JsBuilder` builds the
 * JavaScript value of a scalar. This file states that mapping for the type
 * checker. It declares types only: import it with `import type`.
 *
 * Arrays and plain objects are containers, not scalars, and are not
 * declared here.
 */
import type { VcDate, VcDecimal, VcTimestamp, VcUuid } from './wrappers'

/** A JavaScript value that `JsRef` reads as one scalar. */
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
  | VcUuid
  | undefined
  | null

/**
 * The type `JsBuilder` builds for a scalar that `JsRef` read from a value
 * of type `V`.
 *
 * - A `bigint` comes back as a `bigint`, whatever width it was stored at.
 * - Bytes come back as a `Buffer`, which is a `Uint8Array`.
 * - A `VcTimestamp` comes back as a `Date` when it is whole milliseconds
 *   and within the range of a `Date`, and as a `VcTimestamp` otherwise.
 */
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
                  : V extends VcUuid
                    ? VcUuid
                    : V extends undefined
                      ? undefined
                      : V extends null
                        ? null
                        : never

/**
 * The type `JsBuilder` builds for a scalar of each kind, by the engine's
 * name for the kind. Every integer width is a `bigint`, and both float
 * widths are a `number`.
 *
 * The engine's `json` kind is not here: a JSON document is not a scalar,
 * and the addon converts it.
 */
export interface ScalarKinds {
  bool: boolean
  int8: bigint
  int16: bigint
  int32: bigint
  int64: bigint
  int128: bigint
  uint8: bigint
  uint16: bigint
  uint32: bigint
  uint64: bigint
  uint128: bigint
  float32: number
  float64: number
  decimal: VcDecimal
  date: VcDate
  timestamp: Date | VcTimestamp
  string: string
  bytes: Uint8Array
}
