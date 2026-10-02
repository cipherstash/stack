/**
 * Cooperative exit for first-party command code: `throw new CliExit(code)`
 * instead of `process.exit(code)`.
 *
 * Thrown from a command, it unwinds to `run()` (bin/main.ts), which records the
 * outcome for telemetry, flushes, and then performs the real `process.exit`
 * with the carried code. This only works from call stacks that reach `run()`'s
 * catch without an intervening broad `catch` — which is why ONLY sites verified
 * to unwind cleanly use it (main.ts's own dispatch helpers, the telemetry
 * command, and the outermost CancelledError handlers of init/plan/impl).
 *
 * Deep exits stay `process.exit()` deliberately. An earlier version intercepted
 * `process.exit` globally with a thrown signal; the review showed that breaks
 * code we don't control — @clack/core calls `process.exit(0)` from a keypress
 * handler (no enclosing try ⇒ uncaughtException), and several command-level
 * broad catches swallowed the signal, continuing past hard stops. Those
 * invocations are simply not tracked; see the telemetry module doc.
 */
export class CliExit extends Error {
  constructor(readonly code: number) {
    super(`exit ${code}`)
    this.name = 'CliExit'
  }
}
