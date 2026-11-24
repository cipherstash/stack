import { mkdir, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

/** Write one NDJSON file per Run stage, referenced by its path and digest.
 * @param {string} output
 * @returns {import('../types.js').IsolationTrailWriter}
 */
export function createIsolationTrailWriter(output) {
  return async (stage, body) => {
    const file = `isolation-events/${stage}.ndjson`
    await mkdir(resolve(output, 'isolation-events'), { recursive: true })
    await writeFile(resolve(output, file), body)
    return file
  }
}
