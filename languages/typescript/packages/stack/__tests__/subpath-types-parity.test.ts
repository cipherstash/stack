import { describe, expect, it } from 'vitest'
import packageJson from '../package.json'

// `exports` and `typesVersions` describe the same subpaths to two different
// resolvers, and only one of them is exercised by anything in this repo.
//
// `exports` carries the types for `moduleResolution: "node16"`/`"bundler"`,
// which is what every consumer here uses. A consumer on classic node10
// resolution — still the default for `moduleResolution` when `module` is
// `commonjs`, so not a rarity — reads `typesVersions` instead, and a subpath
// missing from it resolves to `any` with no error at the import site. Nothing
// type-checks that: the package builds, publishes, and installs clean.
//
// So the guard is parity, asserted on the manifest. Adding a subpath means
// adding both, and the failure here names the one that was forgotten.
describe('subpath exports', () => {
  it('declare types for node10 resolution as well as node16', () => {
    const typesVersions = packageJson.typesVersions['*'] as Record<
      string,
      string[]
    >

    // Keyed on what `exports` publishes, so a `typesVersions` entry left behind
    // by a REMOVED subpath is not the failure — it is dead weight, not a
    // consumer-visible gap, and pinning it here would make this test fail for
    // something it is not about.
    const declared: Record<string, string> = {}
    const resolvable: Record<string, string> = {}
    for (const [subpath, target] of Object.entries(packageJson.exports)) {
      if (subpath === '.' || subpath === './package.json') continue
      const key = subpath.slice(2)
      const types = (target as { import?: { types?: string } }).import?.types
      if (types === undefined) continue
      declared[key] = types
      resolvable[key] = typesVersions[key]?.[0] ?? '(no typesVersions entry)'
    }

    // Compared as whole objects: the diff names every subpath at once, rather
    // than failing on the first and hiding the rest.
    expect(resolvable).toEqual(declared)
  })
})
