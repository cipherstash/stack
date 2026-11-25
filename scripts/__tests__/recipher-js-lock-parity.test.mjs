import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The value bridge's test addon must resolve the same napi and vitaminc
 * crates for the bridge as the recipher-js workspace does.
 *
 * The bridge's Node suites run against the test addon
 * (`value-napi/tests/addon`), a Cargo workspace of its own with its own
 * Cargo.lock. The bridge ships in the recipher-js workspace, against the
 * versions that workspace's Cargo.lock resolves. If the two resolve
 * different versions, the suites test a napi or a vitaminc the shipped
 * addon does not run.
 *
 * Each lock is read as a graph, from the `recipher-value-napi` package
 * outwards, and every napi and vitaminc crate the bridge reaches is
 * compared by version, source and checksum. The graph matters: the
 * workspace also builds the engine, which reaches an older vitaminc of its
 * own that the bridge never runs, so comparing every crate a lock names
 * would compare versions the bridge never uses.
 *
 * Node builtins only: no cargo on `pnpm run test:scripts` (see AGENTS.md).
 */

const RECIPHER = 'languages/typescript/packages/recipher-js'
const WORKSPACE_LOCK = `${RECIPHER}/Cargo.lock`
const ADDON_LOCK = `${RECIPHER}/value-napi/tests/addon/Cargo.lock`

/** The crates the two workspaces must agree on. */
const SHARED = /^(napi|vitaminc)(-|$)/

/** The crate whose dependency graph both locks are compared over. */
const BRIDGE = 'recipher-value-napi'

/** Every `[[package]]` a `Cargo.lock` records. */
function lockPackages(source) {
  const field = (block, key) =>
    new RegExp(`^${key} = "([^"]*)"$`, 'm').exec(block)?.[1] ?? null
  return source
    .split(/^\[\[package\]\]$/m)
    .slice(1)
    .map((block) => ({
      name: field(block, 'name'),
      version: field(block, 'version'),
      source: field(block, 'source'),
      checksum: field(block, 'checksum'),
      dependencies: [
        ...(/^dependencies = \[([^\]]*)\]/m.exec(block)?.[1] ?? '').matchAll(
          /"([^"]+)"/g,
        ),
      ].map(([, entry]) => entry),
    }))
}

/**
 * The packages reachable from `root`, following each package's
 * `dependencies`. A lock writes a dependency as `name` when it records one
 * version of that name, and as `name version` (with the source after it, in
 * parentheses, when two sources share a version) when it records several.
 */
function reachable(packages, root) {
  const resolve = (entry) => {
    const [name, version] = entry.split(' ')
    const candidates = packages.filter(
      (pkg) => pkg.name === name && (!version || pkg.version === version),
    )
    if (candidates.length !== 1) {
      throw new Error(
        `cannot resolve the dependency "${entry}": ${candidates.length} packages match`,
      )
    }
    return candidates[0]
  }
  const seen = new Set()
  const stack = [resolve(root)]
  while (stack.length > 0) {
    const pkg = stack.pop()
    if (seen.has(pkg)) continue
    seen.add(pkg)
    stack.push(...pkg.dependencies.map(resolve))
  }
  return [...seen]
}

/**
 * Every napi and vitaminc package the bridge reaches in a `Cargo.lock`, keyed
 * by name, each as its sorted list of version, source and checksum.
 */
function sharedPackages(source) {
  const packages = new Map()
  for (const pkg of reachable(lockPackages(source), BRIDGE)) {
    if (!SHARED.test(pkg.name)) continue
    const entries = packages.get(pkg.name) ?? []
    entries.push({
      version: pkg.version,
      source: pkg.source,
      checksum: pkg.checksum,
    })
    entries.sort((a, b) => a.version.localeCompare(b.version))
    packages.set(pkg.name, entries)
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

  it('compares only what the bridge reaches', () => {
    // The workspace lock names vitaminc-aead twice: the bridge's, and the
    // older one the engine reaches. A walk that read every package would
    // compare both and fail on a difference the suites cannot see.
    const named = lockPackages(read(WORKSPACE_LOCK)).filter(
      (pkg) => pkg.name === 'vitaminc-aead',
    )
    expect(named.length).toBeGreaterThan(1)
    expect(workspace.get('vitaminc-aead')).toHaveLength(1)
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
