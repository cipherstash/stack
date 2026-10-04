import { registry } from '../cli/registry.js'

/**
 * Coerce the raw, argv-derived (command, subcommand) to a fixed vocabulary
 * before telemetry emit.
 *
 * `subcommand` is `argv[1]` (see `parseArgs`): for most commands it's a fixed
 * verb, but for a few it's a free-form positional — `stash wizard "add
 * encryption to patients.ssn"` puts a natural-language prompt (routinely
 * containing table/column names) in that slot. The event allowlist gates
 * property KEYS, not values, so without this an arbitrary user string would
 * leave the machine as the `subcommand` value, breaking the "no table/column
 * names, no argument values" contract. Anything not on the known-verb list
 * collapses to `<other>`, so we learn "a wizard ran" without learning what for.
 */
const OTHER = '<other>'

/**
 * Full command paths (`"eql install"`, `"auth login"`, `"init"`, …) from the
 * registry — the single source of truth that also backs `stash manifest` and
 * `--help` — plus the `telemetry` sub-verbs the registry doesn't enumerate.
 * Hidden (deprecated) descriptors are excluded.
 */
const KNOWN_PATHS: ReadonlySet<string> = new Set([
  ...registry.flatMap((group) =>
    group.commands.filter((c) => !c.hidden).map((c) => c.name),
  ),
  'telemetry status',
  'telemetry enable',
  'telemetry disable',
])

/** The first token of every known path — the set of recognised top-level commands. */
const KNOWN_COMMANDS: ReadonlySet<string> = new Set(
  [...KNOWN_PATHS].map((path) => path.split(' ')[0]),
)

/**
 * Error class names allowed to leave as `errorType`. The same closed-vocabulary
 * rule as commands: the CLI executes USER code in-process (stash.config.ts and
 * the encrypt client, via jiti), so `err.constructor.name` is an open
 * vocabulary — a user-defined `PatientsSsnColumnMissingError` would carry a
 * column name off the machine. First-party classes + Node/JS builtins pass;
 * everything else collapses to `<other>`.
 */
const KNOWN_ERROR_TYPES: ReadonlySet<string> = new Set([
  // JS builtins
  'Error',
  'TypeError',
  'RangeError',
  'SyntaxError',
  'ReferenceError',
  'EvalError',
  'URIError',
  'AggregateError',
  // Node-flavoured
  'AbortError',
  'TimeoutError',
  'SystemError',
  // First-party CLI errors
  'CliExit',
  'CancelledError',
  'BackfillConfigError',
  // Config validation (zod)
  'ZodError',
])

/** Coerce an unknown thrown value to a telemetry-safe error class name. */
export function classifyErrorType(err: unknown): string {
  if (!(err instanceof Error)) return '<other>'
  return KNOWN_ERROR_TYPES.has(err.constructor.name)
    ? err.constructor.name
    : '<other>'
}

/**
 * Return telemetry-safe (command, subcommand). An unrecognised command becomes
 * `<other>` (and drops its subcommand); a recognised command with an
 * unrecognised subcommand keeps the command but reports `<other>` for the
 * subcommand, so a free-text positional never leaves as-is.
 */
export function classifyCommand(
  command: string,
  subcommand: string | undefined,
): { command: string; subcommand: string | undefined } {
  if (!KNOWN_COMMANDS.has(command)) {
    return { command: OTHER, subcommand: undefined }
  }
  if (subcommand === undefined) {
    return { command, subcommand: undefined }
  }
  return KNOWN_PATHS.has(`${command} ${subcommand}`)
    ? { command, subcommand }
    : { command, subcommand: OTHER }
}
