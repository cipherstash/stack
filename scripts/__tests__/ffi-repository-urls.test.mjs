import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The seven FFI manifests must name THIS repository.
 *
 * npm trusted publishing matches `repository.url` against the repository the
 * publish runs from, exactly: *"your package's `repository.url` field in
 * `package.json` must exactly match your GitHub repository"*
 * (https://docs.npmjs.com/trusted-publishers/). A stale URL does not warn and
 * does not degrade — the publish is rejected. All seven still named
 * `cipherstash/protectjs-ffi` after the subtree import, which was correct while
 * they were still published from there and wrong the moment publishing moves.
 *
 * `repository.directory` is the quieter half. It resolves from the ROOT of the
 * repository named in `repository.url`, so `platforms/<p>` addressed a real
 * directory in the old repo and addresses nothing here, where the packages live
 * at `packages/protect-ffi/platforms/<p>`. The two fields fail differently: a
 * stale `url` fails the publish outright, while a `directory` that does not
 * resolve publishes fine and silently breaks the source link on the package
 * page. Only one of those gets noticed, which is why both are asserted.
 */

const FFI = join(REPO_ROOT, 'packages/protect-ffi')

/** The repository these packages publish from as of the cutover. */
const EXPECTED = 'https://github.com/cipherstash/stack'

const PLATFORMS = readdirSync(join(FFI, 'platforms'))

const manifests = [
  join(FFI, 'package.json'),
  ...PLATFORMS.map((platform) => join(FFI, 'platforms', platform, 'package.json')),
]

describe('FFI manifests name this repository', () => {
  it('checks the wrapper and all six platform packages', () => {
    expect(manifests).toHaveLength(7)
  })

  for (const path of manifests) {
    const pkg = JSON.parse(readFileSync(path, 'utf8'))
    it(`${pkg.name} points repository.url at cipherstash/stack`, () => {
      expect(pkg.repository.url).toBe(`git+${EXPECTED}.git`)
    })
  }

  it('the wrapper also updates bugs and homepage', () => {
    // Not required by npm, but a published package that links its users at an
    // archived repository is its own kind of wrong.
    const pkg = JSON.parse(readFileSync(join(FFI, 'package.json'), 'utf8'))
    expect(pkg.bugs.url).toBe(`${EXPECTED}/issues`)
    expect(pkg.homepage).toBe(`${EXPECTED}#readme`)
  })

  for (const platform of PLATFORMS) {
    it(`${platform} names its own path from the repo root`, () => {
      // A host-only rewrite leaves this field alone and the suite would go
      // green on a source link that 404s — these six assertions are what make
      // skipping the `directory` fix visible.
      const pkg = JSON.parse(
        readFileSync(join(FFI, 'platforms', platform, 'package.json'), 'utf8'),
      )
      expect(pkg.repository.directory).toBe(
        `packages/protect-ffi/platforms/${platform}`,
      )
    })
  }

  it('no manifest still references the old repository', () => {
    for (const path of manifests) {
      expect(readFileSync(path, 'utf8')).not.toMatch(/protectjs-ffi/)
    }
  })

  it('the crate manifest names this repository too', () => {
    // `publish = false`, so this is documentation rather than a registry
    // requirement — but the crate manifest ships inside every platform tarball
    // built from this tree, and a wrong URL in a shipped manifest is wrong.
    const cargo = readFileSync(
      join(FFI, 'crates/protect-ffi/Cargo.toml'),
      'utf8',
    )
    expect(cargo).toMatch(
      /^repository = "https:\/\/github\.com\/cipherstash\/stack"$/m,
    )
    expect(cargo).not.toMatch(/protectjs-ffi/)
  })

  it('the crate sends bug reports here, not to the archived repository', () => {
    // `InvariantViolation`'s message is the one repository URL that reaches an
    // end user at runtime — it is compiled into every platform binary and
    // printed when the Rust core hits a state it believes impossible. The old
    // repository is archived at the end of the cutover, and an archived
    // repository accepts no issues, so this link stops working for exactly the
    // people it exists to help.
    const lib = readFileSync(
      join(FFI, 'crates/protect-ffi/src/lib.rs'),
      'utf8',
    )
    expect(lib).not.toMatch(/protectjs-ffi/)
  })
})
