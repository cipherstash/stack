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
 * The auth taxonomy code on a failure that came from `stack-auth` — CTS
 * refused to issue or renew the service token every ZeroKMS request carries.
 *
 * Deliberately a separate field from {@link ProtectErrorCode} rather than more
 * members of it. That set is closed and owned HERE: `errorCodes.test.ts` pins
 * it against the `#[diagnostic(code(..))]` attributes in
 * `crates/protect-ffi/src/lib.rs`, and every member has one. The auth set is
 * owned by `stack-auth` and versioned on its own release train, so folding the
 * two together would either break that test or force this package to re-declare
 * a taxonomy it does not decide.
 *
 * So the type is open on purpose — `(string & {})` keeps editor completion for
 * the named members without rejecting a code from a newer `stack-auth` than the
 * one this build pinned. Narrow with a `===` against a literal; do not
 * `switch` exhaustively.
 *
 * Only the two that carry a caller-actionable remedy are named. The rest of the
 * set (`NOT_AUTHENTICATED`, `WORKSPACE_MISMATCH`, `EXPIRED_TOKEN`, …) still
 * arrives, and is documented in `@cipherstash/auth`'s `AuthFailure` union.
 *
 * - `USAGE_LIMIT_EXCEEDED` — the organisation has used its allowance for the
 *   current billing period. **Not** retryable and **not** a credentials
 *   problem: nothing clears it until the plan is upgraded.
 * - `ORG_NOT_PROVISIONED` — the organisation is not registered with the usage
 *   system at all. There is no plan to upgrade; it needs support.
 *
 * Both arrive alongside `help` — the remedy text — and `url`, the link that
 * goes with it, when the failure carries one. The two are one remedy split
 * across two fields, on the same error and on a `decryptBulkFallible` item;
 * whichever the failure has is set, and a field with no value is absent rather
 * than empty.
 *
 * For a failure raised by a `config.authStrategy`, all three are the ones the
 * strategy's own rejection carried, verbatim — not values re-derived from the
 * `stack-auth` enum, which cannot name a code newer than the pinned crate.
 */
export type ProtectAuthErrorCode =
  | 'USAGE_LIMIT_EXCEEDED'
  | 'ORG_NOT_PROVISIONED'
  | (string & {})

/**
 * Read the auth taxonomy code off a thrown FFI error, if it has one.
 *
 * Present only when the failure came from `stack-auth`; every other failure
 * leaves the field unset, so `undefined` means "not an auth failure" rather
 * than "an auth failure with no code".
 */
export function getAuthErrorCode(
  error: unknown,
): ProtectAuthErrorCode | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const { authCode } = error as { authCode?: unknown }
  return typeof authCode === 'string' ? authCode : undefined
}

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
