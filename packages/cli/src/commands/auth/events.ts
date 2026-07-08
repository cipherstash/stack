/**
 * The newline-delimited JSON (NDJSON) event stream that `--json` auth flows
 * write to stdout. Centralised here so every emitter — `login`, `bindDevice`,
 * and the region resolver — shares one envelope shape; an agent parsing the
 * stream sees a consistent contract no matter which stage produced the event.
 *
 * Native-free by design, so `region.ts` can depend on it without pulling in the
 * `@cipherstash/auth` binary and staying unit-testable under the fast suite.
 */

/** Emit one NDJSON event (one JSON object per line) to stdout. */
export function emitJsonEvent(event: Record<string, unknown>): void {
  console.log(JSON.stringify(event))
}

/**
 * Emit the shared `{ status: 'error', code, message }` envelope. The single
 * source of truth for how a failure surfaces on the NDJSON stream.
 */
export function emitJsonError(code: string, message: string): void {
  emitJsonEvent({ status: 'error', code, message })
}
