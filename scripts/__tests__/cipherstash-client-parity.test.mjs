import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The EQL workspace and protect-ffi must resolve the same crates that compute
 * SteVec selectors: cipherstash-client and cipherstash-config.
 *
 * The SteVec selector pin
 * (`packages/eql/tests/encryption/tests/ste_vec_selectors.rs`) pins the
 * selectors cipherstash-client's `JsonIndexer` derives — the computation every
 * stored SteVec document depends on. The indexer is cipherstash-client's; the
 * `ste_vec` index config it is built from (prefix, array index mode, mode and
 * their defaults) is parsed by cipherstash-config. The pin builds in the EQL
 * workspace, against the versions `packages/eql/Cargo.lock` resolves.
 * Customers' documents are written by protect-ffi, a separate Cargo workspace
 * with its own lockfile. If the two resolve different versions of either
 * crate, the pin passes against code customers do not run, and a
 * protect-ffi-only bump reaches them with the pin still green.
 *
 * Only those two are compared. Primitive dependencies such as blake3 (the
 * selector MAC, a fixed specification) are not, and they already differ at
 * patch level between the two locks.
 *
 * Node builtins only: no cargo on `pnpm run test:scripts` (see AGENTS.md).
 */

const EQL_LOCK = 'packages/eql/Cargo.lock'
const FFI_LOCK = 'languages/typescript/packages/protect-ffi/Cargo.lock'

/** Every version of `name` a `Cargo.lock` records, sorted. */
export function lockedVersions(source, name) {
  return source
    .split(/^\[\[package\]\]$/m)
    .slice(1)
    .filter((block) => new RegExp(`^name = "${name}"$`, 'm').test(block))
    .map((block) => /^version = "([^"]*)"$/m.exec(block)?.[1])
    .filter(Boolean)
    .sort()
}

const read = (file) => readFileSync(join(REPO_ROOT, file), 'utf8')

/** The crates that compute SteVec selectors. */
const SELECTOR_CRATES = ['cipherstash-client', 'cipherstash-config']

describe.each(SELECTOR_CRATES)(
  '%s parity between the EQL workspace and protect-ffi',
  (name) => {
    const eql = lockedVersions(read(EQL_LOCK), name)
    const ffi = lockedVersions(read(FFI_LOCK), name)

    it(`finds exactly one ${name} in each lock`, () => {
      // The floor: a rename or a lock that stops naming the crate would make
      // the comparison below vacuous.
      expect(eql).toHaveLength(1)
      expect(ffi).toHaveLength(1)
    })

    it(`resolves the same ${name} version in both locks`, () => {
      expect(
        eql,
        `${EQL_LOCK} resolves ${name} ${eql}, ${FFI_LOCK} resolves ${ffi}: ` +
          'the SteVec selector pin tests a version protect-ffi does not ship. ' +
          'Move the EQL workspace to match (the cipherstash-client pins in ' +
          'tests/encryption and tests/sqlx; `cargo update -p` for a transitive crate).',
      ).toEqual(ffi)
    })
  },
)
