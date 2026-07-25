import { getErrorCode } from './error-code'

/**
 * `String(value)` that cannot itself throw — a Proxy or a null-prototype
 * object can make it throw, and losing the failure to a second exception
 * inside the error path is the worst outcome available.
 */
function safeString(value: unknown): string {
  try {
    return String(value)
  } catch {
    return Object.prototype.toString.call(value)
  }
}

/**
 * Coerce a rejection into an `Error` WITHOUT losing what it said.
 *
 * Pass as `withResult`'s `onException` hook. Without it, a non-`Error`
 * rejection reaches the failure mapper as-is, `(error as Error).message` is
 * `undefined`, and the detail is replaced by a generic string — a Rust-side
 * string rejection like "boom from rust" becomes "Something went wrong".
 *
 * That mattered enough to be covered on the WASM entry
 * (`wasm-inline-result-contract.test.ts`) and not on the native one, because
 * wasm-bindgen hands back bare strings and plain objects where the NAPI
 * binding throws `Error` subclasses. Sharing the operation classes across both
 * entries (#798) means the shared path has to be the careful one — this is
 * that behaviour, lifted out of `wasm-inline.ts` so both entries get it.
 *
 * The synthesized `Error` carries a structural `code` forward: `withResult`
 * runs `onException` FIRST, so the failure mapper only ever sees this fresh
 * Error. Without copying it, `failure.code` could never be populated for any
 * rejection that was not already an `Error`.
 */
export function toError(ex: unknown): Error {
  if (ex instanceof Error) return ex
  if (typeof ex === 'string') return new Error(ex)

  // Objects are the other shape wasm-bindgen hands back, so serialize rather
  // than settle for "[object Object]". `JSON.stringify` returns undefined for
  // a symbol/function and throws on a cycle.
  let message: string
  try {
    message = JSON.stringify(ex) ?? safeString(ex)
  } catch {
    message = safeString(ex)
  }

  const error = new Error(message) as Error & { code?: string }
  const code = getErrorCode(ex)
  if (code) error.code = code
  return error
}
