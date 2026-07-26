import {
  ProtectError as FfiProtectError,
  type ProtectErrorCode,
} from '@cipherstash/protect-ffi'

/**
 * Extracts FFI error code from an error if it's an FFI error, otherwise returns undefined.
 * Used to preserve specific error codes in ProtectError responses.
 *
 * ## Why this still uses `instanceof`, and what has to change for #798
 *
 * `FfiProtectError` is a *value* import of the Node-API entry, so this module
 * cannot be reached from `@cipherstash/stack/wasm-inline` — importing it puts a
 * bare `@cipherstash/protect-ffi` specifier into `dist/wasm-inline.js`, the one
 * bundle that exists to avoid the native binding. That happened once already
 * (#741), which is why `__tests__/wasm-inline-bundle-isolation.test.ts` asserts
 * against the built artifact.
 *
 * Sharing the operation classes with the WASM entry therefore requires a
 * structural read of `code` instead (the WASM build ships no error class for
 * `instanceof` to match, so a `code` string is all there is to find). That was
 * written and then reverted with the rest of stage 4: it widens what reaches
 * `failure.code`, because any object with a string `code` matches — a Node
 * `ECONNRESET` from inside the FFI would surface as a `ProtectErrorCode` it is
 * not, and `dynamodb/helpers.ts` copies `failure.code` verbatim onto the errors
 * it throws.
 *
 * That widening is acceptable *if* it is a deliberate, released change. It is
 * not acceptable as a silent side effect of an internal refactor, which is what
 * it would have been here. Restore the structural version when stage 4 lands,
 * and say so in the changeset.
 */
export function getErrorCode(error: unknown): ProtectErrorCode | undefined {
  return error instanceof FfiProtectError ? error.code : undefined
}
