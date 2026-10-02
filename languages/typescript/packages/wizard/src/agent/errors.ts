/**
 * Shared error formatting for wizard interactions with the CipherStash
 * AI gateway. Used by both the agent SDK error path and direct fetch
 * calls (e.g. fetchIntegrationPrompt).
 */

const ERROR_FOOTER = `
The CipherStash wizard uses Anthropic's Claude API via a CipherStash-hosted gateway.

  Gateway status:   https://status.cipherstash.com
  Anthropic status: https://status.anthropic.com/

If this issue persists, please contact support@cipherstash.com`.trim()

export function formatWizardError(summary: string, detail?: string): string {
  const parts = [summary]
  if (detail) parts.push(detail)
  parts.push(ERROR_FOOTER)
  return parts.join('\n\n')
}

/**
 * Classify an error from the agent SDK into a user-friendly message.
 * Accepts an optional SDK error code and the raw error message.
 * The runner parameter must be passed explicitly (the detected package manager's execCommand).
 */
export function classifyError(
  errorCode: string | undefined,
  rawMessage: string,
  runner: string,
): string {
  if (errorCode === 'authentication_failed') {
    return formatWizardError(
      'Authentication failed.',
      `Your CipherStash token may be expired or invalid. Run: ${runner} stash auth login`,
    )
  }
  if (errorCode === 'rate_limit') {
    return formatWizardError(
      'Rate limited.',
      'The AI gateway has rate-limited this request. Please wait a moment and try again.',
    )
  }
  if (errorCode === 'billing_error') {
    return formatWizardError(
      'Billing error from Anthropic.',
      'This is a temporary issue with the AI service provider.',
    )
  }

  const apiErrorMatch = rawMessage.match(/API Error: (\d+)\s*(\{.*\})?/s)
  if (apiErrorMatch) {
    const status = Number(apiErrorMatch[1])
    const body = apiErrorMatch[2] ?? ''
    let apiMessage = ''
    try {
      const parsed = JSON.parse(body)
      apiMessage = parsed?.error?.message ?? ''
    } catch {
      apiMessage = body
    }
    return classifyHttpError(status, apiMessage || rawMessage, runner)
  }

  if (
    rawMessage.includes('ECONNREFUSED') ||
    rawMessage.includes('fetch failed')
  ) {
    return formatWizardError(
      'Could not reach the CipherStash AI gateway.',
      'The gateway may be temporarily unavailable. Check the status pages below.',
    )
  }

  if (rawMessage.includes('exited with code')) {
    return formatWizardError(
      'The AI agent process exited unexpectedly.',
      `Detail: ${rawMessage}`,
    )
  }

  return formatWizardError(
    'The wizard encountered an unexpected error.',
    rawMessage,
  )
}

/**
 * Classify an HTTP error from a direct gateway fetch into the same
 * user-friendly format the agent SDK errors use.
 * The runner parameter must be passed explicitly (the detected package manager's execCommand).
 */
export function classifyHttpError(
  status: number,
  apiMessage: string,
  runner: string,
): string {
  if (status === 400) {
    return formatWizardError(
      `The AI gateway rejected the request (HTTP ${status}).`,
      apiMessage ? `Reason: ${apiMessage}` : undefined,
    )
  }
  if (status === 401) {
    return formatWizardError(
      'Authentication failed (HTTP 401).',
      `Your CipherStash token may be expired. Run: ${runner} stash auth login`,
    )
  }
  if (status === 429) {
    return formatWizardError(
      'Rate limited (HTTP 429).',
      'Too many requests to the AI service. Please wait a moment and try again.',
    )
  }
  if (status >= 500) {
    return formatWizardError(
      `The AI service returned an error (HTTP ${status}).`,
      apiMessage
        ? `Reason: ${apiMessage}`
        : 'This is likely a temporary issue.',
    )
  }
  return formatWizardError(
    `The AI service returned an error (HTTP ${status}).`,
    apiMessage || undefined,
  )
}
