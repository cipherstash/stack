import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The value bridge's test addon must resolve the same napi and vitaminc
 * crates as the recipher-js workspace.
 *
 * The bridge's Node suites run against the test addon
 * (`value-napi/tests/addon`), a Cargo workspace of its own with its own
 * Cargo.lock. The bridge ships in the recipher-js workspace, against the
 * versions that workspace's Cargo.lock resolves. If the two resolve
 * different versions, the suites test a napi or a vitaminc the shipped
 * addon does not run.
 *
 * Every napi and vitaminc crate both locks name is compared, by version,
 * source and checksum, so a crate either workspace adds later is covered
 * from the day it lands.
 *
 * Node builtins only: no cargo on `pnpm run test:scripts` (see AGENTS.md).
 */

const RECIPHER = 'languages/typescript/packages/recipher-js'
const WORKSPACE_LOCK = `${RECIPHER}/Cargo.lock`
const ADDON_LOCK = `${RECIPHER}/value-napi/tests/addon/Cargo.lock`

/** The crates the two workspaces must agree on. */
const SHARED = /^(napi|vitaminc)(-|$)/

/**
 * Every package a `Cargo.lock` records whose name matches `SHARED`, keyed by
 * name, each as its sorted list of version, source and checksum.
 */
function sharedPackages(source) {
  const field = (block, key) =>
    new RegExp(`^${key} = "([^"]*)"$`, 'm').exec(block)?.[1] ?? null
  const packages = new Map()
  for (const block of source.split(/^\[\[package\]\]$/m).slice(1)) {
    const name = field(block, 'name')
    if (!name || !SHARED.test(name)) continue
    const entries = packages.get(name) ?? []
    entries.push({
      version: field(block, 'version'),
      source: field(block, 'source'),
      checksum: field(block, 'checksum'),
    })
    entries.sort((a, b) => a.version.localeCompare(b.version))
    packages.set(name, entries)
  }
  return packages
}

const read = (file) => readFileSync(join(REPO_ROOT, file), 'utf8')

describe('napi and vitaminc parity between recipher-js and the test addon', () => {
  const workspace = sharedPackages(read(WORKSPACE_LOCK))
  const addon = sharedPackages(read(ADDON_LOCK))
  const both = [...workspace.keys()].filter((name) => addon.has(name)).sort()

  it('finds the crates it means to compare', () => {
    // The floor: a lock that stopped naming them would make the comparison
    // below vacuous.
    expect(both).toContain('napi')
    expect(both).toContain('vitaminc-aead')
  })

  it.each(both)('resolves the same %s in both locks', (name) => {
    expect(
      addon.get(name),
      `${ADDON_LOCK} resolves ${name} ${JSON.stringify(addon.get(name))}, ` +
        `${WORKSPACE_LOCK} resolves ${JSON.stringify(workspace.get(name))}: ` +
        'the Node suites test a crate the shipped addon does not run. Move ' +
        'the test addon to match with `cargo update -p <crate> --precise ' +
        '<version> --manifest-path value-napi/tests/addon/Cargo.toml`.',
    ).toEqual(workspace.get(name))
  })
})
