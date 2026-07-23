import { existsSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { sharedAlias, stackSourceAlias } from '../../vitest.shared.ts'

// A vite alias pointing at a file that no longer exists fails LATE and badly:
// nothing validates the map, so the entry survives a package refactor and the
// next test to use that specifier gets a "failed to resolve import" on a path
// the author never wrote, instead of the honest "subpath is not exported".
// `@cipherstash/stack-drizzle/v3` sat here for exactly that reason after the
// `./v3` collapse.

/** Directory aliases are written with a trailing slash (`'@/'`). */
const targets = (map) =>
  Object.entries(map).map(([specifier, target]) => [
    specifier,
    target.endsWith('/') ? target.slice(0, -1) : target,
  ])

describe('vitest.shared.ts alias targets exist on disk', () => {
  it('exports both maps, non-empty (guards a silently-renamed export)', () => {
    expect(Object.keys(sharedAlias).length).toBeGreaterThan(5)
    expect(Object.keys(stackSourceAlias).length).toBeGreaterThan(0)
  })

  it.each(targets(sharedAlias))('sharedAlias %s', (_specifier, target) => {
    expect(existsSync(target), `missing alias target: ${target}`).toBe(true)
  })

  it.each(
    targets(stackSourceAlias),
  )('stackSourceAlias %s', (_specifier, target) => {
    expect(existsSync(target), `missing alias target: ${target}`).toBe(true)
  })
})
