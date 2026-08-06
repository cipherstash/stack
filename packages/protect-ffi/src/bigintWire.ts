/**
 * Internal wire encoding for JS `bigint` plaintexts crossing the Neon
 * boundary.
 *
 * The native addon extracts every options object with neon's `Json`
 * extractor, which runs `JSON.stringify` on the JS side — and
 * `JSON.stringify` throws a `TypeError` on any `bigint`. So `bigint`
 * plaintexts are bounds-checked against i64 here (with a clear
 * `RangeError`) and encoded into the tagged single-key map
 * `{"__protect_ffi_bigint__": "<decimal string>"}`, which the Rust side
 * deserializes into `JsPlaintext::BigInt`. The value is a decimal string,
 * not a number: an i64-magnitude number literal would already have lost
 * precision beyond 2^53.
 *
 * The wasm build performs the equivalent encoding in Rust
 * (`encode_plaintext` in `crates/protect-ffi/src/wasm.rs`) because
 * wasm consumers call the wasm-bindgen exports directly, without this
 * wrapper.
 *
 * The decrypt direction needs no decoding: the native addon constructs a
 * real JS `bigint` (`JsBigInt::from_i64` on Neon, `js_sys::BigInt` on
 * wasm).
 */

/** Must match `BIGINT_WIRE_KEY` in `crates/protect-ffi/src/js_plaintext.rs`. */
export const BIGINT_WIRE_KEY = '__protect_ffi_bigint__'

/** Smallest value an encrypted bigint column can store (i64::MIN). */
export const BIGINT_MIN = -(2n ** 63n)
/** Largest value an encrypted bigint column can store (i64::MAX). */
export const BIGINT_MAX = 2n ** 63n - 1n

/** The tagged wire form a `bigint` plaintext crosses the boundary in. */
export type BigIntWire = { [K in typeof BIGINT_WIRE_KEY]: string }

const I64_BOUNDS_SUFFIX =
  'encrypted bigint values must fit in a signed 64-bit integer ' +
  '(-9223372036854775808 to 9223372036854775807)'

/**
 * Encode a `bigint` plaintext into its tagged wire form, throwing a
 * `RangeError` (naming the i64 bounds and the offending direction) when
 * the value does not fit a signed 64-bit integer. Non-`bigint` values pass
 * through untouched. The error deliberately does not echo the value: it is
 * plaintext being encrypted.
 */
export function encodeBigIntPlaintext<T>(
  plaintext: T | bigint,
): T | BigIntWire {
  if (typeof plaintext !== 'bigint') {
    return plaintext
  }
  if (plaintext > BIGINT_MAX) {
    throw new RangeError(
      `BigInt plaintext is above the maximum supported value: ${I64_BOUNDS_SUFFIX}`,
    )
  }
  if (plaintext < BIGINT_MIN) {
    throw new RangeError(
      `BigInt plaintext is below the minimum supported value: ${I64_BOUNDS_SUFFIX}`,
    )
  }
  return { [BIGINT_WIRE_KEY]: plaintext.toString() }
}

/**
 * Return `opts` with a `bigint` `plaintext` replaced by its tagged wire
 * form. When the plaintext is not a `bigint`, the original object is
 * returned unchanged (no clone).
 */
export function withEncodedPlaintext<T extends { plaintext: unknown }>(
  opts: T,
): T {
  // `opts?.` (matching the detection pass in withEncodedPlaintexts): a
  // null/undefined element must fall through to native's own validation
  // error rather than throw a raw property-access TypeError here — the
  // error a bad element produces must not depend on whether a *sibling*
  // element happens to carry a bigint.
  if (typeof opts?.plaintext !== 'bigint') {
    return opts
  }
  return { ...opts, plaintext: encodeBigIntPlaintext(opts.plaintext) }
}

/**
 * Bulk variant of {@link withEncodedPlaintext}: returns the original array
 * (no clone) when no payload carries a `bigint` plaintext.
 */
export function withEncodedPlaintexts<T extends { plaintext: unknown }>(
  payloads: T[],
): T[] {
  if (
    !Array.isArray(payloads) ||
    !payloads.some((p) => typeof p?.plaintext === 'bigint')
  ) {
    return payloads
  }
  return payloads.map(withEncodedPlaintext)
}
