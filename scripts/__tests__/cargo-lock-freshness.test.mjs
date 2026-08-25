import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * Every crate this repo owns must be recorded in every `Cargo.lock` at the
 * version its own `Cargo.toml` declares.
 *
 * ## The drift this catches, and why nothing else does
 *
 * `scripts/sync-lockstep-versions.mjs` rewrites
 * `packages/eql/crates/eql-bindings/Cargo.toml` on every lockstep bump — that
 * is its job. `packages/protect-ffi` depends on that crate BY PATH
 * (`crates/protect-ffi/Cargo.toml`), so its `Cargo.lock` records the version
 * too, and nothing was updating it. After the 3.0.5 bump the lock still said
 * `eql-bindings 3.0.4` and `cargo metadata --locked` exited 101.
 *
 * Nothing failed. Not one command in this repo passes `--locked`:
 * `build:native` is a plain `cargo build --release`, so every CI job that
 * touches Rust silently regenerated the lock, used the regenerated one, and
 * threw it away with the runner. The committed file drifted further from the
 * tree on each lockstep bump while every job stayed green.
 *
 * ## Why a version comparison rather than `cargo metadata --locked`
 *
 * `--locked` is the exact check and it needs a Rust toolchain. `AGENTS.md` is
 * explicit that the default `test` and `build` scripts must never invoke cargo
 * — root `pnpm test` reaches `packages/protect-ffi`, so a cargo call on that
 * path is a Rust toolchain on every contributor's machine — and `pnpm run
 * test:scripts` has the same reach, since everyone runs it.
 *
 * So this asserts the property that actually broke, with node builtins: a
 * source-less `[[package]]` entry in a lock is a crate resolved from this
 * tree, and its version is knowable by reading the crate's manifest. That is
 * narrower than `--locked` — a lock stale because a crate gained a NEW
 * dependency still passes here — but it is the whole of the lockstep failure
 * mode, it runs everywhere, and it costs nothing. Pairing it with a `--locked`
 * invocation on `packages/protect-ffi`'s `test:cargo` path would close the
 * remainder; that script is owned elsewhere.
 */

/** Same skip set, and the same reasons, as `lint-no-eql-registry-pins.mjs`. */
const SKIP_DIRS = new Set([
  '.git',
  '.claude',
  'node_modules',
  'target',
  'dist',
  '.turbo',
  '.next',
])

/** Every file named `name` under the repo, repo-relative and POSIX-spelled. */
function findFiles(name) {
  const found = []
  const walk = (abs) => {
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(join(abs, entry.name))
      } else if (entry.name === name) {
        found.push(join(abs, entry.name))
      }
    }
  }
  walk(REPO_ROOT)
  return found
    .map((abs) => relative(REPO_ROOT, abs).split(sep).join('/'))
    .sort()
}

/**
 * `[package] name` and `version` from one `Cargo.toml`.
 *
 * Anchored to the `[package]` table for the reason `bumpCargoPackageVersion`
 * is: a `[dependencies.foo]` long-form table also carries a column-0
 * `version = "…"` line, and reading "the first version in the file" would pick
 * up whichever came first.
 */
function crateManifest(source) {
  const section = source.match(/^\[package\]\n(?:(?!^\[).*\n)*/m)
  if (!section) return null
  const name = /^name = "([^"]*)"$/m.exec(section[0])
  const version = /^version = "([^"]*)"$/m.exec(section[0])
  return name && version ? { name: name[1], version: version[1] } : null
}

/**
 * The `[[package]]` entries of a `Cargo.lock` that resolve from THIS tree.
 *
 * A registry or git dependency carries a `source = "…"` key; a path dependency
 * and a workspace member carry none. That absence is the whole test for
 * "cargo resolved this from a directory", and it is how cargo itself
 * distinguishes them.
 */
export function localLockEntries(source) {
  return source
    .split(/^\[\[package\]\]$/m)
    .slice(1)
    .map((block) => {
      const name = /^name = "([^"]*)"$/m.exec(block)
      const version = /^version = "([^"]*)"$/m.exec(block)
      const source_ = /^source = "/m.test(block)
      return name && version && !source_
        ? { name: name[1], version: version[1] }
        : null
    })
    .filter(Boolean)
}

/** name -> { version, file } for every crate manifest in the tree. */
const CRATES = new Map()
const AMBIGUOUS = []
for (const file of findFiles('Cargo.toml')) {
  const crate = crateManifest(readFileSync(join(REPO_ROOT, file), 'utf8'))
  if (!crate) continue // a virtual manifest: `[workspace]` with no `[package]`
  const existing = CRATES.get(crate.name)
  if (existing && existing.version !== crate.version) {
    AMBIGUOUS.push(`${crate.name}: ${existing.file} vs ${file}`)
  }
  CRATES.set(crate.name, { ...crate, file })
}

const LOCKS = findFiles('Cargo.lock')

/** Every (lock, local crate) pair, with the version each side records. */
const PAIRS = LOCKS.flatMap((lock) =>
  localLockEntries(readFileSync(join(REPO_ROOT, lock), 'utf8')).map(
    (entry) => ({
      lock,
      name: entry.name,
      locked: entry.version,
      onDisk: CRATES.get(entry.name)?.version ?? null,
    }),
  ),
)

describe('Cargo.lock records this tree’s crates at their real versions', () => {
  it('finds locks and crates to compare', () => {
    // The floor. Discovery over the tree means a walk that stops matching —
    // a new SKIP_DIRS entry, a rename — turns this whole file green while
    // checking nothing.
    expect(LOCKS.length).toBeGreaterThan(0)
    expect(PAIRS.length).toBeGreaterThan(0)
  })

  it('covers eql-bindings, the crate the lockstep bump rewrites', () => {
    // Named specifically because it is the one with a mechanism actively
    // pushing it out of sync: `scripts/sync-lockstep-versions.mjs` writes its
    // `Cargo.toml` on every release. If this crate ever drops out of the pair
    // set, the check that matters most has silently stopped running.
    expect(PAIRS.filter(({ name }) => name === 'eql-bindings').length).toBe(
      LOCKS.length,
    )
  })

  it('resolves every locked local crate to a manifest on disk', () => {
    // A source-less entry naming a crate this tree does not contain means the
    // scan lost its subject — a path dependency pointing outside the repo, or
    // a walk that no longer reaches the crate. Either way the comparison below
    // is not being made, which must not read as a pass.
    expect(
      PAIRS.filter(({ onDisk }) => onDisk === null).map(
        ({ lock, name }) => `${lock} :: ${name}`,
      ),
    ).toEqual([])
  })

  it('has one version per crate name across the tree', () => {
    // The name -> version map is keyed on the crate name alone, so two crates
    // sharing a name at different versions would make the comparison depend on
    // walk order. Fail rather than pick.
    expect(AMBIGUOUS).toEqual([])
  })

  it('locks each crate at the version its Cargo.toml declares', () => {
    // THE DEFECT. `packages/protect-ffi/Cargo.lock` said `eql-bindings 3.0.4`
    // while the crate said 3.0.5, because the lockstep sync rewrote the
    // manifest and no command in this repo passes `--locked`.
    const offenders = PAIRS.filter(
      ({ locked, onDisk }) => locked !== onDisk,
    ).map(
      ({ lock, name, locked, onDisk }) =>
        `${lock}: ${name} locked at ${locked}, ${CRATES.get(name).file} declares ${onDisk}`,
    )
    expect(
      offenders,
      'A committed Cargo.lock disagrees with a crate manifest in this tree. Refresh it with ' +
        '`cargo update --package <crate>` in the workspace holding the lock. Not `--offline`: ' +
        '`cargo update -p` re-resolves the WHOLE graph, so every other package has to come from ' +
        'the local registry cache, and it fails outright on a cold one.',
    ).toEqual([])
  })
})
