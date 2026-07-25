import type { ProtectErrorCode } from '@cipherstash/protect-ffi'

/**
 * Extract an FFI error code from a thrown value, or `undefined`.
 *
 * ## Why this reads structurally rather than with `instanceof`
 *
 * This used to narrow with `error instanceof ProtectError`, which is a *value*
 * import of `@cipherstash/protect-ffi` — the Node-API entry. That made this
 * module unusable from `@cipherstash/stack/wasm-inline`: importing it put a
 * bare `@cipherstash/protect-ffi` specifier into `dist/wasm-inline.js`, the one
 * bundle that exists to avoid the native binding. It happened once already
 * (#741) and was caught only in review, which is why
 * `__tests__/wasm-inline-bundle-isolation.test.ts` now asserts against the
 * built artifact.
 *
 * Sharing the operation classes across both entries (#798) makes that
 * unavoidable rather than merely untidy: the operations call this, so it must
 * be reachable from the WASM bundle. A structural read is the only version that
 * can be — and on that path it is the only version that could ever work, since
 * the WASM build ships no error class for `instanceof` to match. A `code`
 * string is all there is to find.
 *
 * ## The behavioural difference, stated plainly
 *
 * `instanceof` matched only genuine `ProtectError`s. This matches any object
 * carrying a string `code`, so a non-FFI error that happens to have one (a Node
 * `ENOENT`, say) now yields that string where it previously yielded
 * `undefined`. Call sites use the value for reporting, not control flow, so a
 * mislabelled code degrades an error message rather than changing behaviour —
 * and every call site wraps an FFI call, so a non-FFI error arriving here is
 * already the unusual case. The WASM entry has always accepted this tradeoff;
 * this makes both entries accept it identically rather than silently differing.
 */
export function getErrorCode(error: unknown): ProtectErrorCode | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const { code } = error as { code?: unknown }
  return typeof code === 'string' ? (code as ProtectErrorCode) : undefined
}
