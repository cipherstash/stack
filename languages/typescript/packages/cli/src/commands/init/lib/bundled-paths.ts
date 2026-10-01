import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Walk up from the running file looking for a `<name>` directory bundled
 * with the CLI. `tsup` may flatten or preserve the source layout depending
 * on entry / chunking, so we probe several parent depths until one matches.
 *
 * Returns the absolute directory path, or `undefined` if nothing matched —
 * callers warn-and-skip rather than crash so a stripped CLI build still
 * produces something usable.
 *
 * Memoized per directory name; the bundled layout doesn't change at
 * runtime, so we only pay the stat calls once.
 */
const cache = new Map<string, string | undefined>()

export function findBundledDir(name: string): string | undefined {
  const cached = cache.get(name)
  if (cached !== undefined || cache.has(name)) return cached

  const here = currentDir()
  const candidates = [
    join(here, name),
    join(here, '..', name),
    join(here, '..', '..', name),
    join(here, '..', '..', '..', name),
    join(here, '..', '..', '..', '..', name),
    // Dev fallback: running from `packages/cli/src/commands/init/lib/`,
    // the monorepo `<name>/` is six levels up.
    join(here, '..', '..', '..', '..', '..', '..', name),
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      const resolved = resolve(candidate)
      cache.set(name, resolved)
      return resolved
    }
  }
  cache.set(name, undefined)
  return undefined
}

function currentDir(): string {
  if (typeof import.meta?.url === 'string' && import.meta.url) {
    return dirname(fileURLToPath(import.meta.url))
  }
  return __dirname
}
