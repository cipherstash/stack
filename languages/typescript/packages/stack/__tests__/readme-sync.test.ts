/**
 * Guards the npm README against drifting from the root README.
 *
 * `packages/stack/README.md` is a synced copy of the repo root `README.md` —
 * the root file is the single source of truth, and the `prebuild` script
 * copies it into the package before every build (npm cannot publish a
 * symlink, so a real file must ship in the tarball). If someone edits the
 * root README and the copy isn't rebuilt/committed, or edits the package
 * copy directly, this test fails rather than publishing a stale README.
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

describe('package README', () => {
  it('is an exact copy of the root README (synced by prebuild)', () => {
    const pkgReadme = readFileSync(
      fileURLToPath(new URL('../README.md', import.meta.url)),
      'utf8',
    )
    const rootReadme = readFileSync(
      fileURLToPath(new URL('../../../README.md', import.meta.url)),
      'utf8',
    )
    expect(
      pkgReadme,
      'packages/stack/README.md has drifted from the root README — run `pnpm --filter @cipherstash/stack build` and commit the synced copy',
    ).toBe(rootReadme)
  })
})
