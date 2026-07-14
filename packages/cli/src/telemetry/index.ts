import { PostHog } from 'posthog-node'
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

/** The CLI talks to our Cloudflare proxy, not PostHog directly, so that a future
 * US→EU migration is a proxy-target change with no CLI re-release. */
const POSTHOG_HOST = 'https://telemetry.cipherstash.com'

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

/** Interpret an env var as a boolean flag: set to `1`/`true`/`yes` (any case). */
function envFlag(name: string): boolean {
  const raw = process.env[name]
  return raw != null && ['1', 'true', 'yes'].includes(raw.trim().toLowerCase())
}

/** An env var is present with a meaningful (non-empty) value. */
function present(name: string): boolean {
  const raw = process.env[name]
  return raw != null && raw !== ''
}

/** Best-effort CI detection — CI runs are noise and are auto-opted-out. */
function isCI(): boolean {
  return (
    envFlag('CI') ||
    present('CONTINUOUS_INTEGRATION') ||
    present('BUILD_NUMBER') ||
    [
      'GITHUB_ACTIONS',
      'GITLAB_CI',
      'CIRCLECI',
      'TRAVIS',
      'BUILDKITE',
      'JENKINS_URL',
      'TEAMCITY_VERSION',
    ].some(present)
  )
}

/**
 * Resolve whether telemetry is on, in precedence order. Env overrides win over
 * the persisted flag, so a user can force telemetry off in a context where the
 * config file says otherwise (and never the reverse).
 */
export function resolveStatus(state: TelemetryState): TelemetryStatus {
  if (projectKey() === EMBEDDED_KEY) {
    return { enabled: false, reason: 'unconfigured' }
  }
  if (envFlag('DO_NOT_TRACK')) return { enabled: false, reason: 'do-not-track' }
  if (envFlag('STASH_TELEMETRY_DISABLED')) {
    return { enabled: false, reason: 'stash-disabled' }
  }
  if (isCI()) return { enabled: false, reason: 'ci' }
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
      host: POSTHOG_HOST,
      flushAt: 1,
      flushInterval: 0,
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
        ...sanitize({ ...event }),
        ...baseProps(),
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
 * `--json` stdout), then mark it shown. No-op when telemetry is disabled or the
 * notice was already shown. The run that shows it sends nothing (see {@link firstRun}).
 */
export function maybeShowFirstRunNotice(): void {
  if (!status.enabled || !firstRun) return
  if (process.stderr.isTTY) {
    process.stderr.write(`${messages.telemetry.notice}\n`)
  }
  try {
    state = writeState({ ...state, noticeShownAt: new Date().toISOString() })
    status = resolveStatus(state)
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
  try {
    await Promise.race([
      client.shutdown(),
      new Promise((resolve) => setTimeout(resolve, FLUSH_TIMEOUT_MS)),
    ])
  } catch {
    // Swallow — a failed flush must not fail the process.
  } finally {
    client = null
  }
}
