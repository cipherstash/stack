const connectionCodes = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'EPIPE',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'CONNECT_TIMEOUT',
  'CONNECTION_CLOSED',
  'CONNECTION_DESTROYED',
  'CONNECTION_ENDED',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET',
])

/** Preserve retryable store transport failures without hiding app-caused damage.
 * PostgreSQL class 08 is connection errors; 57P01-03 are server shutdown/startup.
 * Schema/data errors and unrecognized failures remain behaviour failures.
 * @param {unknown} error @returns {boolean} */
export function isSnapshotInfrastructureError(error) {
  const seen = new Set()
  while (error && typeof error === 'object' && !seen.has(error)) {
    seen.add(error)
    if ('code' in error && typeof error.code === 'string') {
      if (connectionCodes.has(error.code)) return true
      if (/^[0-9A-Z]{5}$/.test(error.code))
        return (
          /^08[0-9A-Z]{3}$/.test(error.code) || /^57P0[123]$/.test(error.code)
        )
    }
    error = 'cause' in error ? error.cause : undefined
  }
  return false
}
