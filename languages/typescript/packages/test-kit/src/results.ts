/**
 * Unwrap a `@byteslice/result`-shaped `{ data } | { failure }` value in a test,
 * throwing the failure message on the error arm. The integration suites and the
 * ported live suites all assert on the success arm, so this keeps the
 * `if (result.failure) throw` boilerplate in one place rather than re-declaring
 * a local `unwrap()` per file.
 */
export function unwrapResult<T>(result: {
  data?: T
  failure?: { message: string }
}): T {
  if (result.failure) {
    throw new Error(result.failure.message)
  }
  return result.data as T
}
