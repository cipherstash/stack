import { PostHog } from 'posthog-node'
import { isCiEnv } from '../config/tty.js'
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
 *   see {@link sanitize}.
 * - Sending never blocks or slows the CLI: the client is built lazily, flushing
 *   is bounded by a timeout, and every failure is swallowed.
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
 * Public, write-only PostHog project key — safe to embed, exactly like a web
 * SDK key. This literal is replaced with the real key at release (build-time
 * define); `STASH_POSTHOG_KEY` overrides it for testing / self-hosting. Until a
 * real key is present telemetry stays fully dormant: {@link resolveStatus}
 * returns `unconfigured`, so no banner shows and nothing is ever sent.
 */
const EMBEDDED_KEY = '__STASH_POSTHOG_KEY__'

function projectKey(): string {
  return process.env.STASH_POSTHOG_KEY ?? EMBEDDED_KEY
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
  if (projectKey() === EMBEDDED_KEY) {
    return { enabled: false, reason: 'unconfigured' }
  }
  if (envOptOut('DO_NOT_TRACK')) {
    return { enabled: false, reason: 'do-not-track' }
  }
  if (envOptOut('STASH_TELEMETRY_DISABLED')) {
    return { enabled: false, reason: 'stash-disabled' }
  }
  if (isCiEnv()) return { enabled: false, reason: 'ci' }
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

// Module-level state, resolved once per process at import time.
let state = readState()
let status = resolveStatus(state)
/** True when this is the first-ever run (notice not yet shown). It stays true
 * for the whole process even after we persist the notice, so the current run
 * never sends — the freebie. */
const firstRun = state.noticeShownAt === undefined
let cliVersion = '0.0.0'
let client: PostHog | null = null

/** Provide the CLI version for event properties. Call once at startup. */
export function initTelemetry(version: string): void {
  cliVersion = version
}

export function telemetryStatus(): TelemetryStatus {
  return status
}

function getClient(): PostHog {
  if (client === null) {
    client = new PostHog(projectKey(), {
      host: posthogHost(),
      flushAt: 1,
      flushInterval: 0,
      // Fire-and-forget: a short-lived CLI must not retry a failed send. Retries
      // (default 3, exponential backoff) would keep internal timers pending and
      // hang the process for seconds when the endpoint is unreachable, defeating
      // the bounded-flush guarantee. Drop the event instead.
      fetchRetryCount: 0,
      // Never resolve IP → geo; we don't want or store location.
      disableGeoip: true,
    })
  }
  return client
}

function baseProps(): Record<string, unknown> {
  return {
    cliVersion,
    os: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node,
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
  if (!status.enabled || firstRun) return
  try {
    getClient().capture({
      distinctId: state.anonymousId,
      event: 'command_invoked',
      properties: {
        // Sanitize the FULL property set (event + base) so the allowlist is the
        // single enforced boundary — a future prop added to baseProps() can't
        // bypass it. Only the explicit PostHog control key is added afterward.
        ...sanitize({ ...event, ...baseProps() }),
        // Keep events anonymous: no PostHog person profiles.
        $process_person_profile: false,
      },
    })
  } catch {
    // Telemetry must never surface in the command path.
  }
}

/**
 * Show the one-time first-run notice (to stderr, so it never pollutes piped or
 * `--json` stdout) and mark it shown. No-op when telemetry is disabled or the
 * notice was already shown. The run that shows it sends nothing (see {@link firstRun}).
 *
 * `noticeShownAt` is persisted ONLY when the notice was actually displayed —
 * i.e. stderr is a TTY. A non-interactive first run therefore does not consume
 * the freebie: telemetry stays dormant until a real run has shown the disclosure.
 * `stashRef` is the runner-aware invocation (e.g. `npx stash`) so the opt-out
 * hint is actionable before the CLI is on PATH.
 */
export function maybeShowFirstRunNotice(stashRef: string): void {
  if (!status.enabled || !firstRun) return
  if (!process.stderr.isTTY) return
  process.stderr.write(`${messages.telemetry.notice(stashRef)}\n`)
  try {
    writeState({ ...state, noticeShownAt: new Date().toISOString() })
  } catch {
    // A write failure just means we may show the notice again next run.
  }
}

/** Persist the opt-out flag. Surfaces write errors (the command wants to know). */
export function setTelemetryDisabled(disabled: boolean): void {
  state = writeState({ ...state, telemetryDisabled: disabled })
  status = resolveStatus(state)
}

/** Flush any buffered events, bounded by {@link FLUSH_TIMEOUT_MS}. Never throws. */
export async function shutdownTelemetry(): Promise<void> {
  if (client === null) return
  // The timer MUST be cleared once shutdown() wins the race: an uncleared
  // pending setTimeout keeps the Node event loop alive, so the process would
  // hang for the full timeout after the flush already completed.
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
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
    client = null
  }
}
