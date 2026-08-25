import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * Every crate in BOTH nested Cargo workspaces must opt out of crates.io unless
 * it is deliberately allowlisted below.
 *
 * A crate with no `publish` key is publishable BY DEFAULT, and release-plz
 * publishes every workspace member that has not opted out. The convention is
 * exactly one publishable crate per workspace with every other member
 * explicitly `publish = false`, so release-plz needs no per-package
 * configuration.
 *
 * ## Why both, and why that took a second pass
 *
 * This checked `packages/protect-ffi` ONLY, on the reasoning — written in this
 * header — that the repo "is about to grow a crates.io publisher
 * (`eql-bindings`, via release-plz, when `cipherstash/encrypt-query-language`
 * is absorbed)". The absorption happened. The publisher landed as
 * `.github/workflows/release-plz.yml`, pointed by `manifest_path` at
 * `packages/eql/Cargo.toml` — and the workspace it publishes from was the one
 * workspace this file did not read. The check was strictest exactly where
 * nothing could publish and absent where something can.
 *
 * `packages/protect-ffi/crates/protect-ffi` carries no `publish` key and is
 * nonetheless correct: it has never been on crates.io (verified against the
 * registry API), it is a cdylib compiled into `index.node` and shipped inside
 * the six `@cipherstash/protect-ffi-<platform>` npm packages, and nothing
 * publishes that workspace. It stays un-allowlisted because allowlisting means
 * "release-plz will publish this", which is false for it.
 *
 * Each workspace's list below is the audit surface: adding a name means "a
 * release-plz run will publish this crate to crates.io".
 */

const WORKSPACES = [
  {
    // The crates.io publisher's target. `release-plz.yml` passes
    // `manifest_path: packages/eql/Cargo.toml`.
    root: 'packages/eql',
    publishable: new Set(['crates/eql-bindings']),
    // Pinned so an unreadable `members` list fails loudly rather than yielding
    // an empty expansion that passes.
    expects: 'crates/eql-bindings',
  },
  {
    root: 'packages/protect-ffi',
    publishable: new Set(),
    expects: 'crates/protect-ffi',
  },
]

/**
 * The workspace's members, expanded from its own `[workspace] members` list.
 *
 * Read from the manifest rather than by listing `crates/`, because the manifest
 * is what cargo obeys: a member added at a path outside that directory
 * (`members = ["crates/*", "xtask"]`) is one release-plz would publish and a
 * directory scan would never see. The floor guard below then checks the
 * expansion found something, so a members list this parser cannot read fails
 * loudly instead of yielding an empty set that passes.
 */
function workspaceMembers(WORKSPACE) {
  const manifest = readFileSync(join(WORKSPACE, 'Cargo.toml'), 'utf8')
  const block = /^members\s*=\s*\[([^\]]*)\]/m.exec(manifest)?.[1] ?? ''
  return [...block.matchAll(/"([^"]+)"/g)]
    .flatMap(([, pattern]) =>
      pattern.endsWith('/*')
        ? readdirSync(join(WORKSPACE, pattern.slice(0, -2)), {
            withFileTypes: true,
          })
            .filter((entry) => entry.isDirectory())
            .map((entry) => `${pattern.slice(0, -2)}/${entry.name}`)
        : [pattern],
    )
    .sort()
}

describe.each(WORKSPACES)('cargo publish opt-out ($root)', ({
  root,
  publishable,
  expects,
}) => {
  const workspace = join(REPO_ROOT, root)
  const members = workspaceMembers(workspace)

  // The guard on the scan: a discovery test that enumerates nothing passes
  // while checking nothing.
  it('finds the workspace members it means to check', () => {
    expect(members).toContain(expects)
  })

  // The guard on the allowlist: an entry naming a member that no longer
  // exists is an exemption excusing nothing, and it would go on reading as a
  // deliberate decision.
  it('allowlists only real members', () => {
    expect([...publishable].filter((name) => !members.includes(name))).toEqual(
      [],
    )
  })

  for (const member of members) {
    it(`${member} declares publish = false unless allowlisted`, () => {
      if (publishable.has(member)) return
      const manifest = readFileSync(
        join(workspace, member, 'Cargo.toml'),
        'utf8',
      )
      expect(manifest).toMatch(/^publish = false$/m)
    })
  }
})
