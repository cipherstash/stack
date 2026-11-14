import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { lockedPackages } from './lib/cargo-lock.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The Python SDK's workspace and the root workspace must resolve the same
 * crates that decide what a stored value is: the encryption, the order
 * terms, and the key protocol.
 *
 * `languages/python` is its own Cargo workspace, with its own Cargo.lock. Its
 * engine builds the stack-* crates by path, but each lock picks its own
 * versions of the crates from crates.io. The root workspace's tests run the
 * stack crates against the root lock. If the Python lock resolves another
 * version of one of these crates, the Python engine runs code those tests
 * never ran, and it can write values the other SDKs do not read the same way.
 *
 * Each crate is compared by version, source and checksum, as
 * `cipherstash-client-parity.test.mjs` compares its crates. Other shared
 * crates, such as chrono, may differ.
 *
 * The fix for a failure is to seed the Python lock from the root one again,
 * as AGENTS.md describes.
 *
 * Node builtins only: no cargo on `pnpm run test:scripts` (see AGENTS.md).
 */

const ROOT_LOCK = 'Cargo.lock'
const PYTHON_LOCK = 'languages/python/Cargo.lock'

const read = (file) => readFileSync(join(REPO_ROOT, file), 'utf8')
const root = read(ROOT_LOCK)
const python = read(PYTHON_LOCK)

/** Every package name a lock records. */
const names = (lock) =>
  new Set([...lock.matchAll(/^name = "([^"]+)"$/gm)].map((m) => m[1]))

/**
 * The crates that decide what a stored value is. Every vitaminc crate is
 * one: vitaminc is the encryption and the order terms. The rest are named:
 * recipher, and the two order schemes, which the root Cargo.toml pins with
 * `=`; cts-common and zerokms-protocol, the key protocol.
 */
const VALUE_CRATES = [
  ...[...names(root)].filter((name) => name.startsWith('vitaminc')).sort(),
  'recipher',
  'ore-rs',
  'clww-ore',
  'cts-common',
  'zerokms-protocol',
]

const RESEED =
  'Seed it from the root lock again: copy Cargo.lock over ' +
  'languages/python/Cargo.lock, and run `cargo metadata` in languages/python. ' +
  'If cargo moves this crate to a newer version, move it back with ' +
  '`cargo update -p <crate>@<new version> --precise <root version>`.'

describe('the Python lock and the root lock', () => {
  it('both name every crate the comparison checks', () => {
    // The floor: a crate that leaves either lock would make its comparison
    // below compare two empty lists, and pass.
    expect(
      VALUE_CRATES.filter((name) => name.startsWith('vitaminc')).length,
    ).toBeGreaterThan(0)
    const missing = VALUE_CRATES.filter(
      (name) => !names(root).has(name) || !names(python).has(name),
    )
    expect(missing, 'crates missing from one of the two locks').toEqual([])
  })

  it.each(VALUE_CRATES)('resolve the same %s', (name) => {
    const inRoot = lockedPackages(root, name)
    const inPython = lockedPackages(python, name)
    expect(
      inPython,
      `${PYTHON_LOCK} resolves ${name} ${JSON.stringify(inPython)}, and ` +
        `${ROOT_LOCK} resolves ${JSON.stringify(inRoot)}. ${RESEED}`,
    ).toEqual(inRoot)
  })
})
