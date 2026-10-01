import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The seven `@cipherstash/auth` manifests must name THIS repository.
 *
 * `release.yml`'s `publish-auth` publishes them with `--provenance`, and npm
 * refuses a provenance publish (E422) when `repository.url` does not match the
 * repository the attestation names. None of the seven had a `repository` field
 * when they were imported from cipherstash-suite, which published them with a
 * token and no provenance. `ffi-repository-urls.test.mjs` explains why
 * `directory` is asserted as well: a wrong one publishes fine and breaks the
 * source link on the package page.
 *
 * `package.json` is not one of the files the release gate hashes for the auth
 * freeze, so adding the field does not trip it.
 */

const AUTH_DIR = 'languages/typescript/packages/auth'
const AUTH = join(REPO_ROOT, AUTH_DIR)

const EXPECTED_URL = 'git+https://github.com/cipherstash/stack.git'

// Directories only, as ffi-repository-urls.test.mjs does.
const PLATFORMS = readdirSync(join(AUTH, 'platforms'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)

const manifests = [
  { dir: AUTH_DIR, path: join(AUTH, 'package.json') },
  ...PLATFORMS.map((platform) => ({
    dir: `${AUTH_DIR}/platforms/${platform}`,
    path: join(AUTH, 'platforms', platform, 'package.json'),
  })),
]

describe('@cipherstash/auth manifests name this repository', () => {
  it('checks the wrapper and all six platform packages', () => {
    expect(manifests).toHaveLength(7)
  })

  for (const { dir, path } of manifests) {
    const pkg = JSON.parse(readFileSync(path, 'utf8'))

    it(`${pkg.name} points repository.url at cipherstash/stack`, () => {
      expect(pkg.repository?.url).toBe(EXPECTED_URL)
    })

    it(`${pkg.name} names its own path from the repo root`, () => {
      expect(pkg.repository?.directory).toBe(dir)
    })
  }
})
