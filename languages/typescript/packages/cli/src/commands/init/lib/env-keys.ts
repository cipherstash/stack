import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * Names of env keys observed in the project's `.env*` files. We never read or
 * propagate the values — only the names tell the agent which keys to expect.
 *
 * Lives in `lib/` so both `build-schema` (populates `state.envKeys` once at
 * the start of the run) and `gather-context` (reads from state) can import
 * without crossing step boundaries.
 */
export function readEnvKeyNames(cwd: string): string[] {
  const candidates = [
    '.env',
    '.env.local',
    '.env.development',
    '.env.development.local',
  ]
  const seen = new Set<string>()
  for (const file of candidates) {
    const path = resolve(cwd, file)
    if (!existsSync(path)) continue
    let text: string
    try {
      text = readFileSync(path, 'utf-8')
    } catch {
      continue
    }
    for (const line of text.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) continue
      const eq = trimmed.indexOf('=')
      if (eq <= 0) continue
      const key = trimmed.slice(0, eq).trim()
      if (key) seen.add(key)
    }
  }
  return Array.from(seen).sort()
}
