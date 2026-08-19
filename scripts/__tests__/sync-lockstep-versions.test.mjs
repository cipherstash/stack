import { describe, expect, test } from 'vitest'
import {
  bumpCargoPackageVersion,
  cargoLockWorkspaces,
  LOCKED_CRATE,
  refreshCargoLock,
} from '../sync-lockstep-versions.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

const CARGO = `[package]
name = "eql-bindings"
version = "0.4.2"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
`

describe('lockstep Cargo.toml version bump', () => {
  test('rewrites only the [package] version', () => {
    const out = bumpCargoPackageVersion(CARGO, '3.0.0-alpha.7')
    expect(out).toContain('version = "3.0.0-alpha.7"')
    expect(out).toContain('serde = { version = "1", features = ["derive"] }')
    expect(out).not.toContain('version = "0.4.2"')
  })

  test('never rewrites a column-0 version line outside [package]', () => {
    const longFormDeps = `[dependencies.serde]
version = "1"

[package]
name = "eql-bindings"
version = "0.4.2"
`
    const out = bumpCargoPackageVersion(longFormDeps, '3.0.0')
    expect(out).toContain('[dependencies.serde]\nversion = "1"')
    expect(out).toContain('name = "eql-bindings"\nversion = "3.0.0"')
  })

  test('fails loudly when there is no [package] section or version line', () => {
    expect(() =>
      bumpCargoPackageVersion('[dependencies]\nserde = "1"\n', '3.0.0'),
    ).toThrow(/no \[package\] section/)
    expect(() =>
      bumpCargoPackageVersion('[package]\nname = "eql-bindings"\n', '3.0.0'),
    ).toThrow(/did not find a version line/)
  })

  test('round-trips the real crate manifest shape', () => {
    const real = `[package]
name = "eql-bindings"
version = "3.0.0-alpha.2"
edition = "2021"
license = "MIT"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
`
    const out = bumpCargoPackageVersion(real, '3.0.0-alpha.3')
    expect(out.match(/version = "3\.0\.0-alpha\.3"/g)).toHaveLength(1)
    expect(out).toContain('serde_json = "1"')
  })
})

/**
 * The second thing the lockstep bump has to carry, and the one it did not.
 *
 * Rewriting `packages/eql/crates/eql-bindings/Cargo.toml` moves the crate's
 * version. Every `Cargo.lock` that resolves that crate FROM A PATH records the
 * old one, and nothing in this repo passes `--locked`, so the stale lock is
 * regenerated on every CI run, used, and discarded — green the whole way.
 * `cargo metadata --locked` in `packages/protect-ffi` exited 101 for exactly
 * this reason after the 3.0.5 bump.
 *
 * `scripts/__tests__/cargo-lock-freshness.test.mjs` is the guard that fails a
 * PR carrying a stale lock. These are the tests for the half that stops it
 * going stale in the first place.
 */
describe('lockstep Cargo.lock refresh', () => {
  test('discovers every lock that resolves the crate from this tree', () => {
    const found = cargoLockWorkspaces(REPO_ROOT)

    // The floor. Discovery over a hardcoded list means a walk that stops
    // matching refreshes nothing and reports success — so an empty result is a
    // failure, not a no-op. `packages/protect-ffi` is named because it is the
    // consumer that broke: it path-depends on the crate from a SEPARATE cargo
    // workspace, so no eql-side build ever touches its lock.
    expect(found.length).toBeGreaterThan(0)
    expect(found).toContain('packages/protect-ffi')
  })

  test('refreshes offline, through mise, against the named workspace', () => {
    const calls = []
    refreshCargoLock({
      root: '/repo',
      eqlRoot: '/repo/packages/eql',
      workspace: 'packages/protect-ffi',
      run: (...args) => calls.push(args),
    })

    expect(calls).toHaveLength(1)
    const [command, args, options] = calls[0]

    // THROUGH MISE, not a bare `cargo`. release.yml installs mise with
    // `add_shims_to_path: false` — deliberately, so mise's own Node cannot
    // shadow the one `changeset publish` needs — which means cargo is NOT on
    // PATH in the release job. `mise exec` resolves it from
    // packages/eql/mise.toml's `[tools] rust`, which is the same toolchain the
    // SQL build below uses.
    expect(command).toBe('mise')
    expect(args.slice(0, 3)).toEqual(['exec', '--', 'cargo'])
    expect(options.cwd).toBe('/repo/packages/eql')

    // OFFLINE. This runs inside `changeset version`, between the manifest
    // rewrite and the commit; a registry fetch there is a network dependency
    // on the release path buying nothing, because the crate resolves from a
    // path. Verified byte-identical to the networked resolution.
    expect(args).toContain('--offline')
    expect(args).toContain('--package')
    expect(args).toContain(LOCKED_CRATE)
    expect(args).toContain('--manifest-path')
    expect(args).toContain('/repo/packages/protect-ffi/Cargo.toml')
  })

  test('fails loudly rather than leaving a lock stale', () => {
    // A refresh that cannot run must stop the release. The alternative is the
    // state this whole pair of tests exists to end: a bumped manifest, a lock
    // that still names the old version, and a green log.
    expect(() =>
      refreshCargoLock({
        root: '/repo',
        eqlRoot: '/repo/packages/eql',
        workspace: 'packages/protect-ffi',
        run: () => {
          throw new Error('spawn mise ENOENT')
        },
      }),
    ).toThrow(/ENOENT/)
  })
})
