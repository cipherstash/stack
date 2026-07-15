import type { PostHog } from 'posthog-node'
import { isCiEnvBroad, resolveCaller } from '../config/tty.js'
import { messages } from '../messages.js'
import { readState, type TelemetryState, writeState } from './state.js'

/**
 * Anonymous, opt-out CLI usage analytics.
 *
 * Design (see the CLI analytics plan):
 * - Opt-out by default, but **nothing is sent until the first-run notice has
 *   been shown once** — the run that shows it is always a freebie.
 * - Four opt-out gates, any of which disables: `DO_NOT_TRACK`,
 *   `STASH_TELEMETRY_DISABLED`, CI auto-detection, and the persisted
 *   `stash telemetry disable` flag.
 * - Events are anonymous (no PostHog "person" profiles) and carry only a fixed
 *   allowlist of coarse properties. Table/column/schema names, connection
 *   strings, plaintext, ciphertext, and raw argument values can never leave —
 *   {@link sanitize} enforces the key allowlist, and callers must coerce the
 *   VALUES of `command`/`subcommand` to a known vocabulary first (the raw argv
 *   token is a value, not a key, so sanitize alone would pass it through — see
 *   `classifyCommand` in `./classify-command.ts`).
 * - Sending never blocks or slows the CLI: this module reads no disk and loads
 *   no posthog-node until a real event is actually sent (both are deferred off
 *   the `--version`/`--help` fast paths), flushing is bounded by a timeout, and
 *   every failure is swallowed.
 */

/** Default endpoint — our Cloudflare proxy, not PostHog directly, so a future
 * US→EU migration is a proxy-target change with no CLI re-release.
 * `STASH_POSTHOG_HOST` overrides it (testing against a real PostHog ingestion
 * endpoint before the proxy is deployed, or self-hosting), symmetric with
 * `STASH_POSTHOG_KEY`. */
const DEFAULT_POSTHOG_HOST = 'https://telemetry.cipherstash.com'

function posthogHost(): string {
  return process.env.STASH_POSTHOG_HOST ?? DEFAULT_POSTHOG_HOST
}

/**
 * The un-injected sentinel. A build that has NOT embedded a key resolves to
 * exactly this string, and {@link resolveStatus} treats it as "no key" →
 * dormant. It is a plain string literal (not the `__STASH_POSTHOG_KEY__`
 * identifier), so the build-time `define` below never rewrites it.
 */
export const PLACEHOLDER_KEY = '__STASH_POSTHOG_KEY__'

/**
 * Build-time define. The release build (`.github/workflows/release.yml`)
 * replaces the `__STASH_POSTHOG_KEY__` identifier with the real, public,
 * write-only PostHog project key from the `STASH_POSTHOG_KEY` repo variable, via
 * tsup's esbuild `define` (see `tsup.config.ts`). Safe to embed, exactly like a
 * web SDK key. EVERY other build — local dev, a contributor's checkout, a fork,
 * CI unit tests — leaves the identifier undefined, so {@link EMBEDDED_KEY} falls
 * back to {@link PLACEHOLDER_KEY} and telemetry stays fully dormant. The `typeof`
 * guard makes the reference safe even when the identifier was never defined
 * (`typeof undefinedIdent` yields `"undefined"` rather than throwing).
 */
declare const __STASH_POSTHOG_KEY__: string | undefined

const EMBEDDED_KEY =
  typeof __STASH_POSTHOG_KEY__ === 'string' && __STASH_POSTHOG_KEY__.length > 0
    ? __STASH_POSTHOG_KEY__
    : PLACEHOLDER_KEY

/** `STASH_POSTHOG_KEY` in the environment overrides the embedded key entirely
 * (testing / self-hosting); otherwise the build-time value is used. An empty or
 * whitespace-only override counts as unset — otherwise `STASH_POSTHOG_KEY=''`
 * would slip past the nullish fallback and flip a dormant build to "enabled"
 * with an empty key (asymmetric with the `.length > 0` guard on EMBEDDED_KEY). */
function projectKey(): string {
  const override = process.env.STASH_POSTHOG_KEY?.trim()
  return override ? override : EMBEDDED_KEY
}

/** Flush is bounded so a slow or unreachable endpoint can't hang `stash`. */
const FLUSH_TIMEOUT_MS = 1500

export type TelemetryDisabledReason =
  | 'do-not-track'
  | 'stash-disabled'
  | 'ci'
  | 'config'
  | 'unconfigured'

export type TelemetryStatus =
  | { enabled: true }
  | { enabled: false; reason: TelemetryDisabledReason }

/** The only property keys allowed to leave the machine. Everything else is dropped. */
export const ALLOWED_PROP_KEYS: ReadonlySet<string> = new Set([
  'command',
  'subcommand',
  'success',
  'durationMs',
  'errorType',
  'cliVersion',
  'os',
  'arch',
  'nodeVersion',
  'caller',
])

/**
 * An opt-out env var is "set" when present and not an explicit off value. This
 * is deliberately broad: `DO_NOT_TRACK=1`, `=true`, `=on`, or any other non-empty
 * value opts out, matching the DO_NOT_TRACK convention that setting the variable
 * at all signals intent. Only `''`, `'0'`, and `'false'` mean "not opted out".
 */
function envOptOut(name: string): boolean {
  const raw = process.env[name]?.trim().toLowerCase()
  return raw != null && raw !== '' && raw !== '0' && raw !== 'false'
}

/**
 * Resolve whether telemetry is on, in precedence order. Env overrides win over
 * the persisted flag, so a user can force telemetry off in a context where the
 * config file says otherwise (and never the reverse). CI detection is shared
 * with the rest of the CLI via {@link isCiEnv}.
 */
export function resolveStatus(state: TelemetryState): TelemetryStatus {
  // Compare against the sentinel, NOT EMBEDDED_KEY: once a real key is injected
  // at release, EMBEDDED_KEY holds it, and `=== EMBEDDED_KEY` would then read a
  // key-present build (no env override) as unconfigured. The placeholder passing
  // through — no build-time key and no env override — is the "dormant" signal.
  if (projectKey() === PLACEHOLDER_KEY) {
    return { enabled: false, reason: 'unconfigured' }
  }
  if (envOptOut('DO_NOT_TRACK')) {
    return { enabled: false, reason: 'do-not-track' }
  }
  if (envOptOut('STASH_TELEMETRY_DISABLED')) {
    return { enabled: false, reason: 'stash-disabled' }
  }
  if (isCiEnvBroad()) return { enabled: false, reason: 'ci' }
  if (state.telemetryDisabled) return { enabled: false, reason: 'config' }
  return { enabled: true }
}

/** Defence-in-depth: keep only allowlisted keys, whatever a caller passes. */
export function sanitize(
  properties: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(properties)) {
    if (ALLOWED_PROP_KEYS.has(key)) out[key] = value
  }
  return out
}

// Module state is resolved LAZILY on first telemetry use, not at import time, so
// fast paths that never call a telemetry function (`--version`, `--help`) touch
// no disk — the state file read (and its randomUUID on a fresh machine) is
// deferred out of the CLI's hottest paths.
let stateCache: TelemetryState | undefined
let statusCache: TelemetryStatus | undefined
let firstRunCache = false

/**
 * Read the state file once per process and derive status + first-run. Returns
 * the resolved values so callers never touch the (possibly stale) module caches
 * directly. `firstRun` stays true for the whole process even after the notice is
 * persisted, so the current run never sends — the freebie.
 */
function init(): {
  state: TelemetryState
  status: TelemetryStatus
  firstRun: boolean
} {
  if (stateCache === undefined || statusCache === undefined) {
    stateCache = readState()
    statusCache = resolveStatus(stateCache)
    firstRunCache = stateCache.noticeShownAt === undefined
  }
  return { state: stateCache, status: statusCache, firstRun: firstRunCache }
}

let cliVersion = '0.0.0'
// posthog-node is imported dynamically the first time an event is actually sent
// (see getClient), so it is NOT pulled into every `stash` invocation — only when
// telemetry is enabled AND a real command is being tracked. clientPromise is the
// "was anything ever sent this process?" signal shutdownTelemetry gates on.
let clientPromise: Promise<PostHog> | null = null
// The last capture()'s enqueue promise; shutdownTelemetry awaits it before
// flushing so an event fired on an exit path is delivered, not raced away.
let lastCapture: Promise<void> | null = null

/** Provide the CLI version for event properties. Call once at startup. */
export function initTelemetry(version: string): void {
  cliVersion = version
}

export function telemetryStatus(): TelemetryStatus {
  return init().status
}

async function getClient(): Promise<PostHog> {
  if (clientPromise === null) {
    clientPromise = import('posthog-node').then(
      ({ PostHog }) =>
        new PostHog(projectKey(), {
          host: posthogHost(),
          flushAt: 1,
          flushInterval: 0,
          // Fire-and-forget: a short-lived CLI must not retry a failed send.
          // Retries (default 3, exponential backoff) would keep internal timers
          // pending and hang the process. Drop the event instead.
          fetchRetryCount: 0,
          // Bound PostHog's OWN request (undici AbortSignal.timeout). Without
          // this it defaults to 10s, so a black-holed endpoint keeps the socket
          // — and the event loop — alive long past our flush window, defeating
          // the bounded-flush guarantee. Match the flush budget.
          requestTimeout: FLUSH_TIMEOUT_MS,
          // Never resolve IP → geo; we don't want or store location.
          disableGeoip: true,
        }),
    )
  }
  return clientPromise
}

function baseProps(): Record<string, unknown> {
  return {
    cliVersion,
    os: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node,
    // Coarse, fixed-enum classification of the caller (agent harness vs
    // interactive shell). Never the raw env value — see resolveCaller.
    caller: resolveCaller(),
  }
}

export interface CommandEvent {
  command: string
  subcommand?: string
  success: boolean
  durationMs: number
  /** The error constructor name on failure — a class, never a message. */
  errorType?: string
}

/**
 * Record that a command ran. A no-op when telemetry is disabled or on the
 * first run. Never throws.
 */
export function trackCommand(event: CommandEvent): void {
  const { state, status, firstRun } = init()
  if (!status.enabled || firstRun) return
  const properties = {
    // Sanitize the FULL property set (event + base) so the allowlist is the
    // single enforced boundary — a future prop added to baseProps() can't
    // bypass it. Only the explicit PostHog control key is added afterward.
    ...sanitize({ ...event, ...baseProps() }),
    // Keep events anonymous: no PostHog person profiles.
    $process_person_profile: false,
  }
  // Fire-and-forget. getClient() dynamically imports posthog-node only now, so a
  // disabled/dormant run never loads it. shutdownTelemetry awaits lastCapture
  // before flushing so the event is delivered even on process.exit paths.
  lastCapture = getClient()
    .then((client) => {
      client.capture({
        distinctId: state.anonymousId,
        event: 'command_invoked',
        properties,
      })
    })
    .catch(() => {
      // Telemetry must never surface in the command path.
    })
}

/**
 * Show the one-time first-run notice (to stderr, so it never pollutes piped or
 * `--json` stdout) and mark it shown. No-op when telemetry is disabled or the
 * notice was already shown. The run that shows it sends nothing (the freebie).
 *
 * The disclosure is written on EVERY first run, TTY or not — a non-interactive
 * caller (an agent harness, a piped invocation) still gets it in its stderr/log,
 * and `noticeShownAt` is persisted so that machine advances past the freebie and
 * starts sending on its next run. Gating persistence on a TTY (as before) left
 * exactly the agent population the `caller` dimension exists to measure dormant
 * forever. `stashRef` is the runner-aware invocation (e.g. `npx stash`) so the
 * opt-out hint is actionable before the CLI is on PATH.
 */
export function maybeShowFirstRunNotice(stashRef: string): void {
  const { state, status, firstRun } = init()
  if (!status.enabled || !firstRun) return
  process.stderr.write(`${messages.telemetry.notice(stashRef)}\n`)
  try {
    // Reassign the cache: a later setTelemetryDisabled() in the same process
    // must not write from a stale `state` and clobber this noticeShownAt.
    stateCache = writeState({
      ...state,
      noticeShownAt: new Date().toISOString(),
    })
  } catch {
    // A write failure just means we may show the notice again next run.
  }
}

/** Persist the opt-out flag. Surfaces write errors (the command wants to know). */
export function setTelemetryDisabled(disabled: boolean): void {
  const { state } = init()
  stateCache = writeState({ ...state, telemetryDisabled: disabled })
  statusCache = resolveStatus(stateCache)
}

/** Flush any buffered events, bounded by {@link FLUSH_TIMEOUT_MS}. Never throws. */
export async function shutdownTelemetry(): Promise<void> {
  // clientPromise is null iff nothing was ever captured (disabled/dormant/first
  // run), so there is nothing to flush and posthog-node was never loaded.
  if (clientPromise === null) return
  // The timer MUST be cleared once shutdown() wins the race: an uncleared
  // pending setTimeout keeps the Node event loop alive, so the process would
  // hang for the full timeout after the flush already completed.
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    // Wait for the capture enqueue (client construction + queueing) to finish,
    // otherwise shutdown() could race ahead of the event we mean to deliver.
    if (lastCapture !== null) {
      try {
        await lastCapture
      } catch {
        // A failed capture is already swallowed in trackCommand.
      }
    }
    const client = await clientPromise
    await Promise.race([
      client.shutdown(),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, FLUSH_TIMEOUT_MS)
      }),
    ])
  } catch {
    // Swallow — a failed flush must not fail the process.
  } finally {
    if (timer !== undefined) clearTimeout(timer)
    clientPromise = null
    lastCapture = null
  }
}
