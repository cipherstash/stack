import { readFileSync } from 'node:fs'

/**
 * Parse a JSONC file (`turbo.json` and friends allow comments and trailing
 * commas; `JSON.parse` does not).
 *
 * String-aware by necessity, not fussiness: `turbo.json` opens with
 * `"$schema": "https://turbo.build/schema.json"`, so a regex that strips `//`
 * without tracking string state eats the URL and yields invalid JSON — or,
 * worse, silently valid JSON with the wrong contents.
 *
 * Extracted from `turbo-skills-inputs.test.mjs` when a second guard needed it.
 * Two hand-rolled copies of this would drift, and a subtly wrong copy fails as
 * a confusing `SyntaxError` at a byte offset rather than as a clear defect.
 */
export function readJsonc(path) {
  const raw = readFileSync(path, 'utf8')
  let out = ''
  let inString = false
  let escaped = false
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]
    if (inString) {
      out += ch
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === '"') inString = false
      continue
    }
    if (ch === '"') {
      inString = true
      out += ch
      continue
    }
    if (ch === '/' && raw[i + 1] === '/') {
      while (i < raw.length && raw[i] !== '\n') i++
      out += '\n'
      continue
    }
    if (ch === '/' && raw[i + 1] === '*') {
      i += 2
      while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/')) i++
      i++
      continue
    }
    out += ch
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'))
}
