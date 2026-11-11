/** Narrow a stored record or package object without importing application code.
 * @param {unknown} value @returns {Record<string, unknown>} */
export function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw Error('Expected a stored record or package object')
  return Object.fromEntries(Object.entries(value))
}
