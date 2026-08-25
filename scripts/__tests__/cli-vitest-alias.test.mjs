import { existsSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import cliVitestConfig from '../../packages/cli/vitest.config.ts'

/**
 * `packages/cli/vitest.config.ts` carries its own alias map, outside the one
 * `vitest-shared-alias.test.mjs` guards. It has to: closing the CLI suite's
 * remaining build coupling would need `stackSourceAlias`, whose `'@/'` entry
 * points at `packages/stack/src` and would clobber the CLI's own `'@/'`. So the
 * map is package-local and needs its own guard, for the same reason — an alias
 * pointing at a moved file fails LATE, with a "failed to resolve import" naming
 * a path nobody wrote.
 *
 * `@cipherstash/migrate` is pinned by name because it is load-bearing, not
 * cosmetic: without it, 10 files / 177 tests fail to COLLECT on an unbuilt
 * workspace (the transitive `src` importers, not just the one mocked test).
 * `pnpm run test:scripts` runs ahead of the build-dependent suite in CI, so
 * this fires before that failure would (#787 review).
 */

const aliases = cliVitestConfig.resolve.alias

/**
 * Vite also accepts the array form (`[{ find, replacement }]`). This guard
 * reads the object-of-strings form; on the array form every check below would
 * throw `TypeError: target.endsWith is not a function` from a helper, which
 * reads as "the guard is broken" rather than "the config changed shape".
 * Fail here instead, naming the offender.
 */
const nonStringTargets = Object.entries(aliases).filter(
  ([, target]) => typeof target !== 'string',
)

/** Directory aliases are written with a trailing slash (`'@/'`). */
const targets = Object.entries(aliases)
  .filter(([, target]) => typeof target === 'string')
  .map(([specifier, target]) => [
    specifier,
    target.endsWith('/') ? target.slice(0, -1) : target,
  ])

describe('packages/cli vitest alias map', () => {
  it('is the object-of-strings form this guard can read', () => {
    expect(
      nonStringTargets.map(([specifier]) => specifier),
      'packages/cli/vitest.config.ts switched away from the object-of-strings alias form. Update this guard to walk the new shape — do not delete it.',
    ).toEqual([])
  })

  it('still aliases @cipherstash/migrate to source', () => {
    // migrate publishes `./dist` only. Drop this entry — or re-introduce an
    // `importOriginal()` spread that needs the built package — and the unit
    // suite silently regains a dependency on a prior `turbo run build`.
    expect(Object.keys(aliases)).toContain('@cipherstash/migrate')
    expect(aliases['@cipherstash/migrate']).toMatch(
      /packages[/\\]migrate[/\\]src[/\\]index\.ts$/,
    )
  })

  it.each(targets)(
    '%s resolves to a file that exists',
    (_specifier, target) => {
      expect(existsSync(target), `missing alias target: ${target}`).toBe(true)
    },
  )
})
