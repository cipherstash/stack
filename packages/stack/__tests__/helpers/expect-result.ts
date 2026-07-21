import type { Result } from '@byteslice/result'
import type { EncryptionError } from '../../src/errors'

/**
 * Narrow a `Result` to its success arm in tests.
 *
 * `Result<S, F>` is `Success<S> | Failure<F>`, and `Failure` has NO `data`
 * property — so `result.data` doesn't type-check until the union is narrowed.
 * Every assertion on a successful payload would otherwise need its own
 * `if (r.failure) throw` preamble.
 *
 * `F` is pinned to `EncryptionError` rather than left generic: the library
 * constrains it to `FailureCase | Error`, and a bare type parameter neither
 * satisfies that constraint nor lets TypeScript discriminate the union.
 * Every caller here is an encryption operation anyway.
 *
 * Throws (rather than using `expect`) so it stays usable outside an assertion
 * context and reports the failure's own message, which is far more useful than
 * a bare "expected data to be defined".
 */
export function expectData<S>(result: Result<S, EncryptionError>): S {
  if (result.failure) {
    throw new Error(
      `expected { data } but got { failure } (${result.failure.type}): ${result.failure.message}`,
    )
  }
  return result.data
}
