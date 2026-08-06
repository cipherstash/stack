import {
  isProtectErrorCode,
  type ProtectErrorCode,
} from '@cipherstash/protect-ffi'

/**
 * Extracts FFI error code from an error if it's an FFI error, otherwise returns undefined.
 * Used to preserve specific error codes in ProtectError responses.
 *
 * protect-ffi 0.31.0 removed the `ProtectError` class this used to match with
 * `instanceof`. Both bindings now throw an ordinary `Error` with `code` set by
 * Rust, so there is no class left to match — and `instanceof` was unreliable
 * regardless, since it is false across duplicate copies of a package.
 *
 * The check is on the code's *value*, not the presence of a `code` property:
 * Node sets `code` on its own errors, so `ECONNRESET` or `MODULE_NOT_FOUND`
 * would otherwise be reported as an encryption error code.
 */
export function getErrorCode(error: unknown): ProtectErrorCode | undefined {
  const code = (error as { code?: unknown } | null | undefined)?.code
  return isProtectErrorCode(code) ? code : undefined
}
