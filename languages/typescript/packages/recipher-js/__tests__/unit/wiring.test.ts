/**
 * The split between the scripts that need Rust and the ones that do not.
 *
 * Root `pnpm test` runs this package's `test`, and `pnpm build` its
 * `build`, on machines with no Rust toolchain. So neither may run cargo,
 * directly or through another script, and neither may load the native
 * build, which only cargo makes. The suites that load it are reachable from
 * `test:addon` alone, which no turbo task runs.
 */
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const read = (path: string) =>
  readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8')

const manifest = JSON.parse(read('package.json'))
const scripts: Record<string, string> = manifest.scripts

/** Every script `name` runs, following `pnpm run <script>`. */
function reachable(name: string, seen = new Set<string>()): Set<string> {
  if (seen.has(name)) return seen
  seen.add(name)
  const body = scripts[name] ?? ''
  for (const match of body.matchAll(/pnpm (?:run )?([\w:-]+)/g)) {
    const script = match[1]
    if (script !== undefined && script in scripts) {
      reachable(script, seen)
    }
  }
  return seen
}

const RUST = /\bcargo\b|build-native|napi build/

describe('the scripts root `pnpm test` and `pnpm build` reach', () => {
  for (const entry of ['test', 'build']) {
    it(`${entry} runs no cargo`, () => {
      for (const script of reachable(entry)) {
        expect(scripts[script], `${entry} reaches ${script}`).not.toMatch(RUST)
      }
    })
  }

  it('test does not run the suites that load the native build', () => {
    const config = read('vitest.config.ts')
    expect(config).toContain("include: ['__tests__/unit/**/*.test.ts']")
    for (const script of reachable('test')) {
      expect(scripts[script]).not.toContain('vitest.addon.config.ts')
    }
  })

  it('the native build and its tests have scripts of their own', () => {
    expect(scripts['build:native']).toMatch(RUST)
    expect(scripts['build:debug']).toMatch(RUST)
    expect(scripts['test:addon']).toContain('vitest.addon.config.ts')
    expect(scripts['test:cargo']).toContain('cargo test --locked')
  })

  it('both native builds write the committed declarations', () => {
    for (const script of ['build:native', 'build:debug']) {
      expect(scripts[script]).toMatch(/^napi build /)
      expect(scripts[script]).toContain('--dts native.d.ts')
    }
    expect(read('native.d.ts')).toContain('export declare class Cipher')
  })

  it('the package is private, so nothing publishes it', () => {
    expect(manifest.private).toBe(true)
  })
})
