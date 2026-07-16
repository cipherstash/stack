import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { RELEASE_TRAIN_MANIFESTS } from '../../src/release-train.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const CLI_ROOT = path.resolve(__dirname, '../..')

/**
 * Guards the build-time version embed end to end against the BUILT artifact
 * (#661): if the tsup define were dropped, renamed, or fed the wrong shape,
 * the shipped CLI would degrade to bare (dist-tag-resolved) installs. The
 * runtime code paths are covered by unit tests; this asserts the artifact
 * they run in actually carries the embed, with the exact versions of the
 * workspace manifests — the same source tsup reads — so it never needs
 * updating per release.
 *
 * (The behavioural route — driving the built CLI onto the missing-package
 * guidance in a bare temp project — is unreachable under this harness: jiti
 * resolves `stash`/`@cipherstash/stack` from the monorepo's own node_modules
 * regardless of cwd.)
 */
describe('runtime-versions build embed', () => {
  it('the built bundles embed the release-train versions', () => {
    const expected: Record<string, string> = {}
    for (const [pkg, rel] of Object.entries(RELEASE_TRAIN_MANIFESTS)) {
      const manifest = JSON.parse(
        fs.readFileSync(path.resolve(CLI_ROOT, rel), 'utf8'),
      ) as { version: string }
      expected[pkg] = manifest.version
    }

    // Both bundles inline runtime-versions (dist/index for the library entry,
    // the bin chunk for the CLI). Losing the define in either would silently
    // unpin that bundle, so check each.
    const binDir = path.join(CLI_ROOT, 'dist', 'bin')
    const bundles = [
      path.join(CLI_ROOT, 'dist', 'index.js'),
      ...fs
        .readdirSync(binDir)
        .filter((f) => f.endsWith('.js'))
        .map((f) => path.join(binDir, f)),
    ]

    for (const [pkg, version] of Object.entries(expected)) {
      // The embed is a JSON string literal in the bundle; the exact escaping
      // varies by bundler, so assert on the stable `"pkg":"version"` pair
      // (tolerating escaped quotes).
      const pair = new RegExp(
        `\\\\?"${pkg.replace(/[/@]/g, (c) => `\\${c}`)}\\\\?":\\\\?"${version.replace(/\./g, '\\.')}\\\\?"`,
      )
      const found = bundles.some((b) => pair.test(fs.readFileSync(b, 'utf8')))
      expect(found, `${pkg}@${version} embedded in a shipped bundle`).toBe(true)
    }
  })
})
