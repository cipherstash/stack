import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * Every crate in the nested Cargo workspace must opt out of crates.io unless it
 * is deliberately allowlisted below.
 *
 * A crate with no `publish` key is publishable BY DEFAULT, and `protect-ffi`
 * carries none: it has never been on crates.io (verified against the registry
 * API), it is a cdylib compiled into `index.node` and shipped inside the six
 * `@cipherstash/protect-ffi-<platform>` npm packages, and it has no
 * Rust-consumer identity at all. Nothing today would publish it — but this repo
 * is about to grow a crates.io publisher (`eql-bindings`, via release-plz, when
 * `cipherstash/encrypt-query-language` is absorbed), and release-plz publishes
 * every workspace member that has not opted out. The convention EQL already
 * uses, and which this workspace inherits with that import, is exactly one
 * publishable crate with every other member explicitly `publish = false`, so
 * release-plz needs no per-package configuration.
 *
 * The list below is the audit surface: adding a name to it means "a future
 * release-plz run will publish this crate to crates.io".
 */

const CRATES = join(REPO_ROOT, 'packages/protect-ffi/crates')

/** Crates deliberately published to crates.io. Adding a name here is a decision. */
const PUBLISHABLE = new Set([])

describe('cargo publish opt-out', () => {
  const members = readdirSync(CRATES, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)

  // The guard on the scan: a discovery test that enumerates nothing passes
  // while checking nothing.
  it('finds the workspace members it means to check', () => {
    expect(members).toContain('protect-ffi')
  })

  for (const name of members) {
    it(`${name} declares publish = false unless allowlisted`, () => {
      if (PUBLISHABLE.has(name)) return
      const manifest = readFileSync(join(CRATES, name, 'Cargo.toml'), 'utf8')
      expect(manifest).toMatch(/^publish = false$/m)
    })
  }
})
