import {
  isProtectErrorCode,
  type ProtectErrorCode,
} from '@cipherstash/protect-ffi'

/**
 * Extract an FFI error code from a rejection, or `undefined` if it carries none.
 * Used to preserve specific error codes on the way into a `{ failure }` Result.
 *
 * Read STRUCTURALLY, not with `instanceof`. protect-ffi 0.31 removed the
 * `ProtectError` class this used to narrow against: both bindings now throw an
 * ordinary `Error` with `code` set by Rust, so there is nothing to unwrap and no
 * class to match on. The class was unreliable for this anyway — `instanceof` is
 * false across duplicate copies of a package, and the WASM build never shipped
 * one, which is why `wasm-inline.ts` had to grow its own structural reader.
 *
 * `isProtectErrorCode` checks the VALUE, not just the field's presence. Node
 * sets `code` on its own errors, so a bare `typeof code === 'string'` would let
 * an `ECONNRESET` through as though it were an encryption failure.
 */
export function getErrorCode(error: unknown): ProtectErrorCode | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const { code } = error as { code?: unknown }
  return isProtectErrorCode(code) ? code : undefined
}
