import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The EQL manifests must name THIS repository, mirroring
 * ffi-repository-urls.test.mjs.
 *
 * npm trusted publishing matches `repository.url` against the repository the
 * publish runs from, exactly: *"your package's `repository.url` field in
 * `package.json` must exactly match your GitHub repository"*
 * (https://docs.npmjs.com/trusted-publishers/). A stale URL does not warn and
 * does not degrade — the publish is rejected. crates.io applies the same rule
 * to `repository` in Cargo.toml.
 *
 * `repository.directory` is the quieter half. It resolves from the ROOT of the
 * repository named in `repository.url`, so `packages/eql` addressed the real
 * package root in the old repo and addresses nothing here, where the npm
 * package lives at `packages/eql/packages/eql` (the subtree's own nested
 * package.json, per the verbatim-prefix import). A stale `directory` publishes
 * fine and silently breaks the source link on the package page — the failure
 * that gets noticed is the wrong one, which is why both are asserted.
 */

const EQL_NPM = join(REPO_ROOT, 'packages/eql/packages/eql/package.json')
const EQL_BINDINGS_CARGO = join(
  REPO_ROOT,
  'packages/eql/crates/eql-bindings/Cargo.toml',
)

/** The repository these packages publish from as of the cutover. */
const EXPECTED = 'https://github.com/cipherstash/stack'

describe('EQL manifests name this repository', () => {
  const pkg = JSON.parse(readFileSync(EQL_NPM, 'utf8'))

  it('@cipherstash/eql points repository.url at cipherstash/stack', () => {
    expect(pkg.repository.url).toBe(`git+${EXPECTED}.git`)
  })

  it('@cipherstash/eql names its own path from the repo root', () => {
    expect(pkg.repository.directory).toBe('packages/eql/packages/eql')
  })

  it('@cipherstash/eql sends bug reports here, not to the old repository', () => {
    expect(pkg.bugs.url).toBe(`${EXPECTED}/issues`)
  })

  it('no reference to the old repository remains in package.json', () => {
    expect(readFileSync(EQL_NPM, 'utf8')).not.toMatch(/encrypt-query-language/)
  })

  it('eql-bindings names this repository too', () => {
    const cargo = readFileSync(EQL_BINDINGS_CARGO, 'utf8')
    expect(cargo).toMatch(
      /^repository = "https:\/\/github\.com\/cipherstash\/stack"$/m,
    )
    expect(cargo).toMatch(
      /^homepage = "https:\/\/github\.com\/cipherstash\/stack"$/m,
    )
    expect(cargo).not.toMatch(/encrypt-query-language/)
  })
})
