/**
 * `--chunk-size` validation, shared by every backfill-shaped command.
 *
 * The flag arrives as text from argv and is coerced with `Number(...)`, so
 * `--chunk-size abc` used to reach the backfill engine as `NaN`. The engine
 * binds it straight into the page query's `LIMIT $n`, so Postgres refused it
 * — but only after the dual-write gate had been recorded and the manifest
 * written, and under the generic "Backfill failed" message that deliberately
 * hides the database's text. Negatives and fractions failed the same way.
 * `0` was worse: `LIMIT 0` returns no rows, which the engine reads as
 * "nothing left to do" and reports as a completed backfill.
 *
 * This module is the one place that decides what a chunk size is, so
 * `encrypt backfill` and `decrypt backfill` cannot disagree.
 */

/**
 * Thrown by {@link parseChunkSize} for a value that is not a positive whole
 * number. The message is author-controlled, names the flag and quotes exactly
 * what was received, and carries no row data — safe to print verbatim.
 */
export class InvalidChunkSizeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidChunkSizeError'
  }
}

/**
 * Parse a `--chunk-size` value into the number of rows per chunk.
 *
 * Accepts the flag's raw argv text (so the error can quote what the user
 * typed) or an already-coerced number (what a command handler receives).
 * Anything that is not a positive whole number — `abc`, `0`, `-5`, `1.5`,
 * `NaN`, `1e3`, an empty string — throws {@link InvalidChunkSizeError}.
 *
 * Text is matched as plain decimal digits rather than through `Number(...)`,
 * so `0x10`, `1e3` and `Infinity` are rejected: a chunk size is a row count,
 * and the only sensible spelling is one a user would read back the same way.
 */
export function parseChunkSize(input: string | number): number {
  const value =
    typeof input === 'string'
      ? /^\s*\d+\s*$/.test(input)
        ? Number(input)
        : Number.NaN
      : input

  if (!Number.isSafeInteger(value) || value < 1) {
    const received =
      typeof input === 'string' ? JSON.stringify(input) : String(input)
    throw new InvalidChunkSizeError(
      `--chunk-size must be a positive whole number of rows (got ${received}).`,
    )
  }

  return value
}

/**
 * {@link parseChunkSize} with a default: `undefined` (the flag was not
 * given) yields `fallback`, anything else is validated.
 */
export function resolveChunkSize(
  input: string | number | undefined,
  fallback: number,
): number {
  return input === undefined ? fallback : parseChunkSize(input)
}
