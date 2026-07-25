import type { Context } from '@cipherstash/protect-ffi'

/** A lock context, or the raw `{ identityClaim }` it wraps. */
export type LockContextInput = { identityContext: Context } | Context

/**
 * Normalise a lock-context input to the `Context` protect-ffi expects.
 * Synchronous — no token round-trip.
 *
 * Lives apart from `identity/index.ts` so the operation classes can reach it
 * without pulling that module's `@/utils/config` import, which uses `fs` and
 * `path`. Those are fatal in a Worker or Edge runtime, and the shared
 * operations are imported by `@cipherstash/stack/wasm-inline` (#798).
 *
 * The check is purely STRUCTURAL. `identity/index.ts` used
 * `input instanceof LockContext || 'identityContext' in input`, where the
 * structural half already existed to catch a `LockContext` built in another
 * realm or from a duplicate module instance. That half alone is sufficient —
 * anything the `instanceof` matched, the property check matches too — so
 * dropping it costs no behaviour and removes a value import of the class.
 */
export function resolveLockContext(input: LockContextInput): Context {
  return 'identityContext' in input ? input.identityContext : input
}
