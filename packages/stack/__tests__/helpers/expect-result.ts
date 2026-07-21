import type { WasmResult } from '../../src/wasm-inline'

/**
 * Narrow a `WasmResult` to its success arm in tests.
 *
 * `WasmResult<S>` is a `{ data } | { failure }` union, so `result.data` does
 * not type-check until it is narrowed. Every assertion on a successful payload
 * would otherwise need its own `if (r.failure) throw` preamble.
 *
 * Typed against `WasmResult` specifically, NOT `@byteslice/result`'s `Result`:
 * inference across the two unions collapses `S` to `S | undefined`, so every
 * downstream property access reads as possibly-undefined.
 *
 * Throws (rather than using `expect`) so it stays usable outside an assertion
 * context and reports the failure's own message, which is far more useful than
 * a bare "expected data to be defined".
 */
export function expectData<S>(result: WasmResult<S>): S {
  if (result.failure) {
    throw new Error(
      `expected { data } but got { failure } (${result.failure.type}): ${result.failure.message}`,
    )
  }
  return result.data as S
}
