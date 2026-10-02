/**
 * Every database connection the CLI opens must go through the TLS-aware
 * config layer in `src/db/` — otherwise it silently skips sslmode/sslrootcert
 * handling, the bundled Supabase CA, and the shaped certificate errors, and
 * re-opens the exact gap this layer closed (`encrypt backfill`'s `pg.Pool`
 * was the fifteenth site, missed because the sweep counted `pg.Client`).
 *
 * Same spirit as protect-ffi's `lintWiring.test.ts`: a rule that only lives
 * in review comments is a rule the sixteenth site will break. Enforced form:
 * any `new pg.Client(` / `new pg.Pool(` in `src/` production code must either
 * be `src/db/client.ts` (the factory itself) or pass `buildPgClientConfig`
 * within the constructor call. Test files are exempt — live suites connect
 * to local fixtures with URLs they build themselves.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC_ROOT = join(__dirname, '..', '..')

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === 'node_modules') continue
      out.push(...sourceFiles(full))
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) {
      out.push(full)
    }
  }
  return out
}

describe('pg construction routes through the TLS config layer', () => {
  it('no bare new pg.Client(...) / new pg.Pool(...) outside src/db/client.ts', () => {
    const offenders: string[] = []
    for (const file of sourceFiles(SRC_ROOT)) {
      const rel = relative(SRC_ROOT, file).split(sep).join('/')
      if (rel === 'db/client.ts') continue
      const content = readFileSync(file, 'utf-8')
      const pattern = /new pg\.(?:Client|Pool)\(/g
      for (const match of content.matchAll(pattern)) {
        // The constructor's argument must involve buildPgClientConfig —
        // inspect the text immediately following the call site (covers both
        // `new pg.Client(buildPgClientConfig(url))` and the pool's
        // `{ ...buildPgClientConfig(url), max: 2 }` spread form).
        const argWindow = content.slice(
          match.index,
          match.index + match[0].length + 120,
        )
        if (!argWindow.includes('buildPgClientConfig')) {
          offenders.push(`${rel}: ${argWindow.split('\n')[0]}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })
})
