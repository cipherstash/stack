import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { INTEGRATION_ADAPTER_PACKAGES } from '../commands/init/steps/install-deps.js'
import { RELEASE_TRAIN_MANIFESTS } from '../release-train.js'

const CLI_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')

// The growth guard for #661: `RELEASE_TRAIN_MANIFESTS` is the single source
// the build embeds versions from, and `INTEGRATION_ADAPTER_PACKAGES` is what
// init installs. An adapter present in the second but absent from the first
// would install UNPINNED and be invisible to the skew warning — silently
// reintroducing the dist-tag failure mode on exactly the newest package. This
// suite turns that omission into a red test.
describe('release train coverage', () => {
  it('every integration adapter package rides the release train', () => {
    for (const pkg of Object.values(INTEGRATION_ADAPTER_PACKAGES)) {
      expect(
        RELEASE_TRAIN_MANIFESTS,
        `${pkg} is installed by init but missing from RELEASE_TRAIN_MANIFESTS — it would install unpinned`,
      ).toHaveProperty([pkg])
    }
  })

  it('the core packages and every one-shot-executed package are on the train', () => {
    // stash: init self-installs it; @cipherstash/stack: the client;
    // @cipherstash/wizard: EXECUTED via `npx` from `stash wizard` / the impl
    // handoff, so an unpinned run would execute a different release.
    for (const pkg of ['stash', '@cipherstash/stack', '@cipherstash/wizard']) {
      expect(RELEASE_TRAIN_MANIFESTS).toHaveProperty([pkg])
    }
  })

  it('every train manifest exists and carries a version (what tsup will embed)', () => {
    // Exercises the exact inputs tsup.config.ts reads at build time, so a
    // renamed/moved workspace package fails HERE in source-mode tests, not
    // only at the next build.
    for (const [pkg, rel] of Object.entries(RELEASE_TRAIN_MANIFESTS)) {
      const manifest: unknown = JSON.parse(
        readFileSync(resolve(CLI_ROOT, rel), 'utf8'),
      )
      const m = manifest as { name?: unknown; version?: unknown }
      expect(m.name, `${rel} package name`).toBe(pkg)
      expect(typeof m.version, `${pkg} version`).toBe('string')
      expect((m.version as string).length).toBeGreaterThan(0)
    }
  })
})
