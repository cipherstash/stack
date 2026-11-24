import { isDeepStrictEqual } from 'node:util'

/** @param {unknown} actual @param {unknown} expected */
export function equal(actual, expected) {
  if (!isDeepStrictEqual(actual, expected))
    throw Error('Unexpected application result')
}

/** @param {unknown} error */
export function safePostgresCause(error) {
  if (
    error &&
    typeof error === 'object' &&
    'code' in error &&
    typeof error.code === 'string' &&
    /^(?:[0-9A-Z]{5}|ECONNRESET|ECONNREFUSED|ETIMEDOUT)$/.test(error.code)
  )
    return `PostgreSQL application failed (${error.code})`
  if (
    error instanceof Error &&
    [
      'Unexpected application result',
      'Missing DATABASE_URL',
      'Legacy encryption operation failed',
      'Stack encryption operation failed',
    ].includes(error.message)
  )
    return error.message
  return 'PostgreSQL application failed (details withheld)'
}

/** @param {import('../types.js').OracleCheck[]} checks
 * @param {(error:unknown)=>string} cause */
export function createCheck(
  checks,
  cause = (error) => (error instanceof Error ? error.message : String(error)),
) {
  /** @param {string} id @param {()=>Promise<unknown>} action */
  return async (id, action) => {
    try {
      await action()
      checks.push({ id, passed: true })
    } catch (error) {
      checks.push({ id, passed: false, cause: cause(error) })
    }
  }
}
