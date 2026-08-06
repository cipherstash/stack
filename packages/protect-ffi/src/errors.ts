/**
 * Every code an error crossing the FFI boundary can carry.
 *
 * Declared once, as a value, with the type derived from it — a hand-written
 * union alongside a hand-written runtime list is two things to keep in step,
 * and this list already has to agree with a third: the
 * `#[diagnostic(code(..))]` attributes on `Error` in
 * `crates/protect-ffi/src/lib.rs`, which is where the codes are decided.
 * `errorCodes.test.ts` reads that file and proves the two agree.
 *
 * `UNKNOWN` is the exception: it is a name for "this error had no code", not
 * something Rust emits. An error with no code of its own — the
 * `#[error(transparent)]` wrappers around cipherstash-client failures — simply
 * arrives without the field.
 */
export const PROTECT_ERROR_CODES = [
  'INVARIANT_VIOLATION',
  'UNKNOWN_QUERY_OP',
  'UNKNOWN_COLUMN',
  'MISSING_INDEX',
  'INVALID_QUERY_INPUT',
  'SHORT_MATCH_NEEDLE',
  'INVALID_JSON_PATH',
  'STE_VEC_REQUIRES_JSON_CAST_AS',
  'MATCH_REQUIRES_TEXT',
  'UNSUPPORTED_CONFIG_VERSION',
  'INVALID_EQL_VERSION',
  'EQL_V3_UNSUPPORTED_COLUMN',
  'EQL_V3_CONVERSION_FAILED',
  'INVALID_CIPHERTEXT',
  'UNKNOWN',
] as const

export type ProtectErrorCode = (typeof PROTECT_ERROR_CODES)[number]

const KNOWN_CODES: ReadonlySet<string> = new Set(PROTECT_ERROR_CODES)

/**
 * True when `value` is one of this library's error codes.
 *
 * This is the whole of the error API. Both bindings throw an ordinary JS
 * `Error` with `code` set by Rust, so there is nothing to unwrap and no class
 * to match on — but TypeScript types a `catch` variable as `unknown`, so a
 * caller has to narrow once:
 *
 * ```ts
 * try {
 *   await encryptQuery(client, opts)
 * } catch (err) {
 *   const { code } = err as { code?: unknown }
 *   if (isProtectErrorCode(code) && code === 'INVALID_JSON_PATH') {
 *     // ...
 *   }
 *   throw err
 * }
 * ```
 *
 * Checking the value rather than just the field's presence is the point: Node
 * sets `code` on its own errors, so an `ECONNRESET` would otherwise pass for
 * one of these.
 *
 * There used to be a `ProtectError` class, and a `normalizeError` that caught
 * every failure on the way out and re-threw it as one. It existed to make
 * `instanceof` work, which cost a rewritten stack trace, made the Neon and wasm
 * entries throw different things, and was unreliable anyway — `instanceof` is
 * false across duplicate copies of a package. Once Rust started setting `code`
 * there was nothing left for that layer to add (#146).
 */
export function isProtectErrorCode(value: unknown): value is ProtectErrorCode {
  return typeof value === 'string' && KNOWN_CODES.has(value)
}
