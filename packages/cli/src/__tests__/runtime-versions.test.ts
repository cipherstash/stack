import { describe, expect, it } from 'vitest'
import {
  expectedVersion,
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

describe('runtime-versions (explicit version map)', () => {
  const versions = {
    stash: '1.0.0-rc.2',
    '@cipherstash/stack': '1.0.0-rc.2',
    '@cipherstash/prisma-next': '0.4.0-rc.2',
  }

  it('pins known packages to the release version', () => {
    expect(pinnedSpec('@cipherstash/stack', versions)).toBe(
      '@cipherstash/stack@1.0.0-rc.2',
    )
    // prisma-next versions on its own line — the map, not a shared constant,
    // is the source of truth.
    expect(pinnedSpec('@cipherstash/prisma-next', versions)).toBe(
      '@cipherstash/prisma-next@0.4.0-rc.2',
    )
  })

  it('leaves unknown packages unpinned', () => {
    expect(pinnedSpec('@cipherstash/stack-drizzle', versions)).toBe(
      '@cipherstash/stack-drizzle',
    )
  })

  it('expectedVersion reads the map', () => {
    expect(expectedVersion('stash', versions)).toBe('1.0.0-rc.2')
    expect(expectedVersion('nope', versions)).toBeUndefined()
  })
})
