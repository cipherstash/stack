/**
 * PostHog analytics for the CipherStash Wizard.
 *
 * Tracks wizard interactions, framework detection, completion rates, and errors.
 * Analytics are non-blocking — failures are silently ignored.
 *
 * Honors the same opt-outs as the `stash` CLI's telemetry: `DO_NOT_TRACK`
 * (cross-tool standard), `STASH_TELEMETRY_DISABLED`, and CI auto-detection.
 * The wizard is usually spawned by `stash wizard`, whose first-run notice
 * promises those opt-outs on behalf of the whole CLI surface — this module
 * must not make that promise false.
 */

import { randomUUID } from 'node:crypto'
import { PostHog } from 'posthog-node'
import { POSTHOG_API_KEY, POSTHOG_HOST } from './constants.js'
import type { Integration, WizardSession } from './types.js'

let client: PostHog | undefined

/**
 * An opt-out env var is "set" when present and not an explicit off value —
 * matching the DO_NOT_TRACK convention (and the CLI's `envOptOut`) that setting
 * the variable at all signals intent.
 */
function envOptOut(name: string): boolean {
  const raw = process.env[name]?.trim().toLowerCase()
  return raw != null && raw !== '' && raw !== '0' && raw !== 'false'
}

function analyticsDisabled(): boolean {
  return (
    envOptOut('DO_NOT_TRACK') ||
    envOptOut('STASH_TELEMETRY_DISABLED') ||
    Boolean(process.env.CI?.trim())
  )
}

function getClient(): PostHog | undefined {
  if (!POSTHOG_API_KEY) return undefined
  if (analyticsDisabled()) return undefined

  if (!client) {
    client = new PostHog(POSTHOG_API_KEY, {
      host: POSTHOG_HOST,
      flushAt: 1,
      flushInterval: 0,
      // Never resolve IP → geo.
      disableGeoip: true,
    })
  }

  return client
}

/**
 * Per-process random identifier. Deliberately NOT derived from anything
 * identifying: the previous sha256(username@hostname) was reversible by
 * brute-forcing common username/hostname pairs. Session-stable is enough for
 * funnel analysis within one wizard run; cross-run identity is not worth an
 * identifying hash.
 */
const SESSION_ID = randomUUID()

function getDistinctId(): string {
  return SESSION_ID
}

// --- Event tracking ---

export function trackWizardStarted(session: WizardSession) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard started',
    properties: {
      integration_detected: session.detectedIntegration ?? 'none',
      has_typescript: session.hasTypeScript,
      package_manager: session.detectedPackageManager?.name ?? 'unknown',
    },
  })
}

export function trackFrameworkDetected(integration: Integration | undefined) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard framework detected',
    properties: {
      integration: integration ?? 'none',
      auto_detected: integration !== undefined,
    },
  })
}

export function trackFrameworkSelected(
  integration: Integration,
  wasAutoDetected: boolean,
) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard framework selected',
    properties: {
      integration,
      auto_detected: wasAutoDetected,
    },
  })
}

export function trackAgentStarted(integration: Integration) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard agent started',
    properties: { integration },
  })
}

export function trackWizardCompleted(
  integration: Integration,
  durationMs: number,
) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard completed',
    properties: {
      integration,
      duration_ms: durationMs,
    },
  })
}

/**
 * `error` must be a FIXED LABEL or an error class name — never a raw
 * message. Agent/DB error messages routinely embed file paths, table/column
 * names, and connection-string fragments; those must not leave the machine.
 */
export function trackWizardError(error: string, integration?: Integration) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard error',
    properties: {
      error,
      integration: integration ?? 'unknown',
    },
  })
}

export function trackPrerequisiteMissing(missing: string[]) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard prerequisite missing',
    properties: {
      missing,
      count: missing.length,
    },
  })
}

export function trackHealthCheckResult(
  result: 'ready' | 'not_ready' | 'ready_with_warnings',
) {
  getClient()?.capture({
    distinctId: getDistinctId(),
    event: 'wizard health check',
    properties: { result },
  })
}

/** Flush pending events and shut down. Call before process exit. */
export async function shutdownAnalytics() {
  try {
    await client?.shutdown()
  } catch {
    // Silently ignore shutdown errors
  }
}
