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
 * Emit the shared `{ status: 'error', code, message }` envelope, plus `hint`
 * when the failure carries one. The single source of truth for how a failure
 * surfaces on the NDJSON stream.
 *
 * `hint` is the same remedy the interactive path prints as a follow-up line —
 * "upgrade the plan at dashboard.cipherstash.com", "contact support" — and it
 * belongs here because `--json` exists FOR consumers that never see the clack
 * output. Omitting the key entirely when there is no hint keeps the envelope
 * byte-identical for every failure that had none, so this is additive: an
 * existing parser sees `status`/`code`/`message` exactly as before.
 *
 * Any `{cli}` placeholder must be resolved by the caller — an unsubstituted
 * token is not machine-readable guidance.
 */
export function emitJsonError(
  code: string,
  message: string,
  hint?: string,
): void {
  emitJsonEvent({ status: 'error', code, message, ...(hint ? { hint } : {}) })
}
