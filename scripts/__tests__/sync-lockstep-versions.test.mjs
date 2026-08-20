import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, describe, expect, test } from 'vitest'
import {
  bumpCargoPackageVersion,
  cargoLockWorkspaces,
  LOCKED_CRATE,
  refreshCargoLock,
} from '../sync-lockstep-versions.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

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

/** One `refreshCargoLock` call, as `[command, args, options]`. */
function captureRefresh() {
  const calls = []
  refreshCargoLock({
    root: '/repo',
    eqlRoot: '/repo/packages/eql',
    workspace: 'packages/protect-ffi',
    run: (...args) => calls.push(args),
  })
  expect(calls).toHaveLength(1)
  return calls[0]
}

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

  test('refreshes through mise, against the named workspace', () => {
    const [command, args, options] = captureRefresh()

    // THROUGH MISE, not a bare `cargo`. release.yml installs mise with
    // `add_shims_to_path: false` — deliberately, so mise's own Node cannot
    // shadow the one `changeset publish` needs — which means cargo is NOT on
    // PATH in the release job. `mise exec` resolves it from
    // packages/eql/mise.toml's `[tools] rust`, which is the same toolchain the
    // SQL build below uses.
    expect(command).toBe('mise')
    expect(args.slice(0, 3)).toEqual(['exec', '--', 'cargo'])
    expect(options.cwd).toBe('/repo/packages/eql')

    expect(args).toContain('--package')
    expect(args).toContain(LOCKED_CRATE)
    expect(args).toContain('--manifest-path')
    expect(args).toContain('/repo/packages/protect-ffi/Cargo.toml')
  })

  /**
   * NOT `--offline`, and the reason is a property of the job this runs in.
   *
   * `--offline` reads as free here — `eql-bindings` resolves from a path, so
   * why would refreshing it need a registry? Because `cargo update -p X` does
   * not update X in isolation: it re-resolves the WHOLE graph and rewrites a
   * complete lock, and in offline mode every other package has to come from
   * the local registry cache. `packages/protect-ffi` has 167 of them.
   *
   * The release job has no such cache. `jdx/mise-action` runs there with
   * `install: true, cache: false` — it installs toolchains and populates
   * nothing under `~/.cargo/registry` — and
   * `scripts/lint-no-workflow-caching.mjs` forbids any cache restore in a
   * workflow that publishes. So the first call dies:
   *
   *   error: no matching package named `chrono` found
   *   location searched: crates.io index
   *
   * — with `execFileSync` throwing, `pnpm run version` failing, and no Version
   * Packages PR, AFTER `changeset version` has already rewritten every manifest
   * and CHANGELOG in a job holding `contents: write`. That is the same
   * half-applied-release failure the mise-install step above exists to prevent.
   *
   * The measurement that made `--offline` look safe was taken on a developer
   * machine with a warm `~/.cargo`. Both resolutions agree — verified on the
   * 3.0.4 -> 3.0.5 bump, byte-identical including the `windows-sys` edges cargo
   * repaired along the way — so dropping the flag changes nothing except
   * whether the step can run at all where it actually runs.
   */
  test('does not pass --offline, which cannot resolve on a cold registry', () => {
    const [, args] = captureRefresh()
    expect(args).not.toContain('--offline')
  })

  test('the release job offers no warm cargo registry to resolve against', () => {
    // The other half of the pair above, asserted against CI rather than
    // restated in a comment: if this ever stops being true — someone warms the
    // registry deliberately — then `--offline` becomes available again, and
    // the test that forbids it should be revisited rather than worked around.
    const steps = readWorkflow('.github/workflows/release.yml').jobs.release
      .steps

    const mise = steps.find((s) =>
      (s.uses ?? '').startsWith('jdx/mise-action@'),
    )
    expect(mise, 'release.yml no longer installs mise').toBeDefined()
    expect(mise.with.cache).toBe(false)

    expect(
      steps.filter((s) => /\bactions\/cache\b/.test(s.uses ?? '')),
      'a cache restore in the publishing workflow',
    ).toEqual([])

    expect(
      steps.filter((s) => /cargo\s+(fetch|vendor)/.test(s.run ?? '')),
      'a step that warms the cargo registry',
    ).toEqual([])
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

/**
 * The guard that decides whether any of the above runs at all.
 *
 * `main()` is invoked behind an "am I the entry point?" check. Written as
 * ``import.meta.url === `file://${process.argv[1]}` `` that check compares a
 * percent-encoded URL against a raw path, so a checkout directory containing a
 * space makes it false and the whole script becomes a silent exit 0.
 *
 * That is worse than a crash because of how it is called. `package.json`'s
 * `version` script is `changeset version && node
 * scripts/sync-lockstep-versions.mjs`: exit 0 means `&&` reports success, so
 * `changeset version` bumps the npm package while the crate bump, the
 * `Cargo.lock` refresh and the SQL regeneration are all skipped — the exact
 * lockstep skew this script exists to prevent, committed as a Version Packages
 * PR. CI cannot see it (`/home/runner/work/stack/stack` has no space); a local
 * `pnpm run version` from a spaced path can.
 *
 * So this executes the REAL script against a throwaway tree, twice, at two
 * paths differing only by a space. Asserting the source text would not have
 * caught the original: it read as a perfectly ordinary main-guard.
 */
describe('lockstep main-guard', () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'sync-lockstep-')))
  afterAll(() => rmSync(base, { recursive: true, force: true }))

  // `realpathSync` above is load-bearing, and not about spaces. macOS's
  // `os.tmpdir()` is `/var/folders/...`, a symlink to `/private/var/...`; Node
  // realpaths the main module's `import.meta.url` but not `process.argv[1]`, so
  // an unresolved fixture path makes BOTH guard forms false and the test fails
  // for a reason that has nothing to do with the bug under test.

  /**
   * Build a minimal monorepo skeleton at `<base>/<dirName>`, run the real
   * script from it, and report what happened.
   *
   * Only the first two steps of `main()` can complete here: there is no
   * `Cargo.lock` in the fixture, so step 3's discovery finds nothing and throws
   * before `mise` is ever spawned. That is the point — the crate manifest is
   * rewritten first, so the fixture proves `main()` ran without needing a Rust
   * toolchain, and the loud failure proves it did not quietly stop either.
   */
  function runFrom(dirName) {
    const root = join(base, dirName)
    const cargoPath = join(root, 'packages/eql/crates/eql-bindings/Cargo.toml')
    const pkgPath = join(root, 'packages/eql/packages/eql/package.json')

    mkdirSync(join(root, 'scripts'), { recursive: true })
    mkdirSync(dirname(cargoPath), { recursive: true })
    mkdirSync(dirname(pkgPath), { recursive: true })

    const script = join(root, 'scripts/sync-lockstep-versions.mjs')
    copyFileSync(join(REPO_ROOT, 'scripts/sync-lockstep-versions.mjs'), script)
    writeFileSync(
      pkgPath,
      `${JSON.stringify({ name: '@cipherstash/eql', version: '9.9.9' }, null, 2)}\n`,
    )
    writeFileSync(
      cargoPath,
      '[package]\nname = "eql-bindings"\nversion = "0.0.0-fixture"\n',
    )

    const run = spawnSync(process.execPath, [script], {
      cwd: root,
      encoding: 'utf8',
    })
    return { ...run, cargo: readFileSync(cargoPath, 'utf8') }
  }

  test('fires from a checkout path containing a space', () => {
    const { status, cargo, stderr } = runFrom('dir with space')

    // Did `main()` run at all? Step 2 is the first observable effect.
    expect(
      cargo,
      'the crate manifest was never rewritten: `main()` did not run',
    ).toContain('version = "9.9.9"')

    // And it must not have exited 0 — `&&` in the `version` script reads a
    // zero exit as "the lockstep bump is complete".
    expect(status, `script exited 0 silently; stderr: ${stderr}`).not.toBe(0)
    expect(stderr).toMatch(/no Cargo\.lock/)
  })

  test('behaves identically where the path has no space', () => {
    // The control. Without it, a fixture broken for some unrelated reason
    // would look like the bug — and, after the fix, like the fix working.
    const { status, cargo, stderr } = runFrom('dir-without-space')
    expect(cargo).toContain('version = "9.9.9"')
    expect(status).not.toBe(0)
    expect(stderr).toMatch(/no Cargo\.lock/)
  })
})

/**
 * The invariant the whole script exists to maintain, asserted against the
 * committed tree.
 *
 * `scripts/__tests__/cargo-lock-freshness.test.mjs` compares each `Cargo.lock`
 * entry against that crate's own `Cargo.toml`, which catches a PARTIALLY
 * applied bump — but on a TOTAL no-op (the main-guard above never firing) lock
 * and manifest both stay at the old version, agree with each other, and the
 * suite passes. `release-version-hook.test.mjs` asserts the workflow routes
 * through `pnpm run version`, not that anything happened when it did.
 *
 * Nothing asserted the one equality that a silent no-op cannot satisfy: the npm
 * package's version IS the crate's version. One version, five artefacts.
 */
test('the npm package and the crate ship at the same version', () => {
  const pkg = JSON.parse(
    readFileSync(
      join(REPO_ROOT, 'packages/eql/packages/eql/package.json'),
      'utf8',
    ),
  )
  const cargo = readFileSync(
    join(REPO_ROOT, 'packages/eql/crates/eql-bindings/Cargo.toml'),
    'utf8',
  )
  const crateVersion = cargo
    .match(/^\[package\]\n(?:(?!^\[).*\n)*/m)?.[0]
    .match(/^version = "([^"]*)"$/m)?.[1]

  expect(
    crateVersion,
    'no [package] version in the eql-bindings manifest',
  ).toBeDefined()
  expect(
    crateVersion,
    `@cipherstash/eql is at ${pkg.version} but eql-bindings is at ` +
      `${crateVersion}. Either \`pnpm run version\` did not run its second ` +
      'half, or a version was hand-edited in one place only — the SQL bundle, ' +
      'the crate, the npm package, the docs and the postgres-eql image all ' +
      'ship at one version.',
  ).toBe(pkg.version)
})
