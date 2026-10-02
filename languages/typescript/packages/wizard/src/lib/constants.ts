import type { Integration } from './types.js'

/** Ordered list of integrations — framework-specific before generic. */
export const INTEGRATIONS: Integration[] = [
  'drizzle',
  'supabase',
  'prisma',
  'generic',
]

/**
 * CipherStash LLM gateway endpoint.
 *
 * Only overridable via CIPHERSTASH_WIZARD_GATEWAY_URL in development
 * (NODE_ENV !== 'production'). In production, always uses the official gateway
 * to prevent token exfiltration via env var manipulation.
 */
export const GATEWAY_URL =
  process.env.NODE_ENV !== 'production' &&
  process.env.CIPHERSTASH_WIZARD_GATEWAY_URL
    ? process.env.CIPHERSTASH_WIZARD_GATEWAY_URL
    : 'https://wizard.getstash.sh'

/** CipherStash API endpoint. */
export const CIPHERSTASH_API_URL =
  process.env.CIPHERSTASH_API_URL ?? 'https://api.cipherstash.com'

/** PostHog analytics configuration. */
export const POSTHOG_API_KEY = process.env.CIPHERSTASH_WIZARD_POSTHOG_KEY ?? ''
export const POSTHOG_HOST =
  process.env.CIPHERSTASH_WIZARD_POSTHOG_HOST ?? 'https://us.i.posthog.com'

/** Detection timeout per framework (ms). */
export const DETECTION_TIMEOUT_MS = 10_000

/** Health check timeout (ms). */
export const HEALTH_CHECK_TIMEOUT_MS = 10_000

/** Minimum Node.js version. */
export const MIN_NODE_VERSION = '22.0.0'

/** GitHub issues URL. */
export const ISSUES_URL = 'https://github.com/cipherstash/stack/issues'
