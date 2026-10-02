import { GATEWAY_URL, HEALTH_CHECK_TIMEOUT_MS } from '../lib/constants.js'
import type { HealthCheckResult, ReadinessResult } from '../lib/types.js'

async function checkEndpoint(
  name: string,
  url: string,
): Promise<HealthCheckResult> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), HEALTH_CHECK_TIMEOUT_MS)

  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
    })

    if (response.ok) {
      return { service: name, status: 'up' }
    }

    return {
      service: name,
      status: 'degraded',
      message: `HTTP ${response.status}`,
    }
  } catch (error) {
    return {
      service: name,
      status: 'down',
      message: error instanceof Error ? error.message : 'Unknown error',
    }
  } finally {
    clearTimeout(timeout)
  }
}

/** Required services that block execution if down. */
const BLOCKING_SERVICES = ['gateway']

/**
 * Check readiness of all required services.
 *
 * Returns 'ready' if all services are up,
 * 'ready_with_warnings' if non-blocking services are degraded,
 * 'not_ready' if any blocking service is down.
 */
export async function checkReadiness(): Promise<ReadinessResult> {
  const baseUrl = GATEWAY_URL.replace(/\/+$/, '')
  const checks = await Promise.all([
    checkEndpoint('gateway', `${baseUrl}/health`),
    checkEndpoint('npm', 'https://registry.npmjs.org/'),
  ])

  const hasBlockingUnavailable = checks.some(
    (c) => BLOCKING_SERVICES.includes(c.service) && c.status !== 'up',
  )

  if (hasBlockingUnavailable) return 'not_ready'

  const hasAnyDegraded = checks.some((c) => c.status !== 'up')
  if (hasAnyDegraded) return 'ready_with_warnings'

  return 'ready'
}
