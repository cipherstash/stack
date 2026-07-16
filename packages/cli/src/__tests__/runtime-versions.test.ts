import { describe, expect, it } from 'vitest'
import {
  compareVersions,
  expectedVersion,
  parseEmbeddedVersions,
  pinnedSpec,
  RUNTIME_PACKAGE_VERSIONS,
} from '../runtime-versions.js'

// Source-mode runs (this test) never see the tsup define, so the embedded map
// must be empty and every helper must degrade to the unpinned behaviour —
// that fallback is itself part of the contract (dev/`tsx` runs keep working).
describe('runtime-versions (no build-time embed)', () => {
  it('exposes an empty version map', () => {
    expect(RUNTIME_PACKAGE_VERSIONS).toEqual({})
  })

  it('pinnedSpec falls back to the bare package name', () => {
    expect(pinnedSpec('@cipherstash/stack')).toBe('@cipherstash/stack')
  })

  it('expectedVersion is undefined', () => {
    expect(expectedVersion('@cipherstash/stack')).toBeUndefined()
  })
})

// The embed parser is what stands between a build defect and silently
// unpinned installs (#661): absent (source mode) is fine; present-but-broken
// must THROW, never degrade to {}.
describe('parseEmbeddedVersions', () => {
  it('absent embed (source mode) yields an empty map', () => {
    expect(parseEmbeddedVersions(undefined)).toEqual({})
  })

  it('parses a valid embed', () => {
    expect(
      parseEmbeddedVersions('{"stash":"9.9.9-test.1","@x/y":"8.8.8-test.2"}'),
    ).toEqual({ stash: '9.9.9-test.1', '@x/y': '8.8.8-test.2' })
  })

  it('throws on unparseable JSON instead of degrading to unpinned', () => {
    expect(() => parseEmbeddedVersions('{not json')).toThrow(
      /build defect.*not valid JSON/s,
    )
  })

  it('throws on a non-object shape', () => {
    expect(() => parseEmbeddedVersions('["stash"]')).toThrow(
      /not a plain object/,
    )
    expect(() => parseEmbeddedVersions('null')).toThrow(/not a plain object/)
    expect(() => parseEmbeddedVersions('"9.9.9"')).toThrow(/not a plain object/)
  })

  it('throws on a missing/non-string version value', () => {
    expect(() => parseEmbeddedVersions('{"stash":""}')).toThrow(
      /usable version for "stash"/,
    )
    expect(() => parseEmbeddedVersions('{"stash":42}')).toThrow(
      /usable version for "stash"/,
    )
  })
})

describe('runtime-versions (explicit version map)', () => {
  // Arbitrary FIXTURE versions, deliberately unreal: these tests assert the
  // map is threaded through verbatim, not that any actual release exists.
  // Real versions are never hard-coded anywhere — the shipped map is read
  // from the workspace manifests at build time (tsup.config.ts).
  const versions = {
    stash: '9.9.9-test.1',
    '@cipherstash/stack': '9.9.9-test.1',
    '@cipherstash/prisma-next': '8.8.8-test.2',
  }

  it('pins known packages to the release version', () => {
    expect(pinnedSpec('@cipherstash/stack', versions)).toBe(
      '@cipherstash/stack@9.9.9-test.1',
    )
    // prisma-next versions on its own line — the map, not a shared constant,
    // is the source of truth.
    expect(pinnedSpec('@cipherstash/prisma-next', versions)).toBe(
      '@cipherstash/prisma-next@8.8.8-test.2',
    )
  })

  it('leaves unknown packages unpinned', () => {
    expect(pinnedSpec('@cipherstash/not-on-the-train', versions)).toBe(
      '@cipherstash/not-on-the-train',
    )
  })

  it('expectedVersion reads the map', () => {
    expect(expectedVersion('stash', versions)).toBe('9.9.9-test.1')
    expect(expectedVersion('nope', versions)).toBeUndefined()
  })
})

// Precedence per semver §11, over the shapes this repo actually publishes.
describe('compareVersions', () => {
  it('orders numeric cores', () => {
    expect(compareVersions('0.19.0', '1.0.0-rc.1')).toBe(-1)
    expect(compareVersions('1.1.0', '1.0.9')).toBe(1)
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0)
  })

  it('a release outranks its own prereleases', () => {
    expect(compareVersions('1.0.0', '1.0.0-rc.9')).toBe(1)
    expect(compareVersions('1.0.0-rc.9', '1.0.0')).toBe(-1)
  })

  it('orders prerelease identifiers numerically, not lexically', () => {
    expect(compareVersions('1.0.0-rc.2', '1.0.0-rc.1')).toBe(1)
    // Lexical comparison would get this one wrong ('10' < '2').
    expect(compareVersions('1.0.0-rc.10', '1.0.0-rc.2')).toBe(1)
    expect(compareVersions('1.0.0-rc.1', '1.0.0-rc.1')).toBe(0)
  })

  it('numeric identifiers sort below alphanumeric; shorter below longer', () => {
    expect(compareVersions('1.0.0-1', '1.0.0-alpha')).toBe(-1)
    expect(compareVersions('1.0.0-rc', '1.0.0-rc.1')).toBe(-1)
  })
})
