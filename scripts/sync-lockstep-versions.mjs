// Propagate the changesets-computed npm version to the rest of the EQL release.
//
// `@cipherstash/eql`'s package.json version (owned by `changeset version`) is the
// single source of truth for the EQL release identity V. SQL, the Rust crate,
// and the npm package all ship at V (they're generated from one catalog at one
// commit). This runs as the second half of the root `version` script — right
// after `changeset version` — so the resulting "Version Packages" commit is a
// complete, consistent lockstep bump (which release-plz then publishes verbatim
// from the committed tree).
//
// It (paths relative to the monorepo root):
//   1. reads V from packages/eql/packages/eql/package.json,
//   2. sets packages/eql/crates/eql-bindings/Cargo.toml [package] version = V,
//   3. re-resolves that crate in every Cargo.lock that records it from a path,
//   4. runs `mise run release:prepare_bindings_assets --version V`, which builds
//      the exact-version SQL and writes it (+ release manifests) into both the
//      crate and the npm package.
//
// Step 3 is not decoration. Step 2 moves a version that `packages/protect-ffi`'s
// SEPARATE cargo workspace has pinned in its own lock, and nothing else updates
// it — `packages/eql`'s lock is refreshed as a side effect of step 4, that one
// by nothing at all. Since no command in this repo passes `--locked`, the stale
// lock is silently regenerated on every CI run and the committed file drifts
// further out on each bump. `scripts/__tests__/cargo-lock-freshness.test.mjs`
// fails a PR that carries the drift; step 3 is what stops producing it.

import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

// Set the `[package]` section's version in Cargo.toml text. Anchored to the
// section header rather than "first `version = ...` line in the file" so a
// dependency table that happens to carry a column-0 `version = "..."` line
// (e.g. `[dependencies.foo]` long form) can never be rewritten by mistake.
// Exported for scripts/__tests__/sync-lockstep-versions.test.mjs.
export function bumpCargoPackageVersion(cargo, version) {
  const packageSection = cargo.match(/^\[package\]\n(?:(?!^\[).*\n)*/m)
  if (!packageSection) {
    throw new Error('no [package] section found in Cargo.toml')
  }
  const updated = packageSection[0].replace(
    /^version = "[^"]*"$/m,
    `version = "${version}"`,
  )
  if (updated === packageSection[0]) {
    throw new Error('did not find a version line in the [package] section')
  }
  return cargo.replace(packageSection[0], updated)
}

/** The crate whose version step 2 above moves, and every lock therefore records. */
export const LOCKED_CRATE = 'eql-bindings'

/** Directories the lock scan does not descend into — same set, same reasons, as
 * `scripts/lint-no-eql-registry-pins.mjs`. `target` and `node_modules` are the
 * load-bearing two: both are full of OTHER packages' lockfiles. */
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'target',
  'dist',
  '.turbo',
  '.next',
])

/**
 * Every cargo workspace whose `Cargo.lock` resolves `LOCKED_CRATE` from this
 * tree, repo-relative.
 *
 * DISCOVERED, not listed. The crate is consumed across cargo workspace
 * boundaries — `packages/protect-ffi/crates/protect-ffi/Cargo.toml` reaches it
 * by `path = "../../../eql/crates/eql-bindings"` — and a hardcoded list is
 * exactly what was missing before: `packages/eql`'s own lock is refreshed as a
 * side effect of the SQL build below, `packages/protect-ffi`'s was refreshed by
 * nothing, and no one noticed because no command in this repo passes
 * `--locked`.
 *
 * A registry or git dependency carries a `source = "…"` key in the lock; a path
 * dependency carries none, which is how cargo itself tells them apart and the
 * only test needed here.
 */
export function cargoLockWorkspaces(root) {
  const found = []
  const walk = (abs) => {
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(join(abs, entry.name))
        continue
      }
      if (entry.name !== 'Cargo.lock') continue
      const lock = readFileSync(join(abs, entry.name), 'utf8')
      const records = lock
        .split(/^\[\[package\]\]$/m)
        .slice(1)
        .some(
          (block) =>
            new RegExp(`^name = "${LOCKED_CRATE}"$`, 'm').test(block) &&
            !/^source = "/m.test(block),
        )
      if (records) found.push(relative(root, abs).split(sep).join('/'))
    }
  }
  walk(root)
  return found.sort()
}

/**
 * Re-resolve `LOCKED_CRATE` in one workspace's `Cargo.lock`.
 *
 * THROUGH `mise exec`, not a bare `cargo`. `release.yml` installs mise with
 * `add_shims_to_path: false` — deliberately, so mise's Node cannot shadow the
 * one `changeset publish` shells out to — which leaves cargo off PATH in that
 * job. `mise exec`, run from the EQL root, resolves it from
 * `packages/eql/mise.toml`'s `[tools] rust`: the same toolchain that compiles
 * `eql-codegen` for the SQL build a few lines below, so there is one Rust here
 * rather than two.
 *
 * `--offline` because the crate resolves from a path and needs no registry.
 * Confirmed byte-identical to the networked resolution on the 3.0.4 -> 3.0.5
 * bump, including the four unrelated `windows-sys` edges cargo repaired along
 * the way. A release-time step should not acquire a network dependency it has
 * no use for.
 *
 * `--manifest-path` rather than a second `cwd`, so every cargo invocation in
 * this script runs from the one directory whose mise config is trusted.
 *
 * `run` is injected for the unit tests: what matters is the argv, and asserting
 * it must not require a Rust toolchain on the machine running `test:scripts`.
 */
export function refreshCargoLock({
  root,
  eqlRoot,
  workspace,
  run = execFileSync,
}) {
  run(
    'mise',
    [
      'exec',
      '--',
      'cargo',
      'update',
      '--offline',
      '--package',
      LOCKED_CRATE,
      '--manifest-path',
      join(root, workspace, 'Cargo.toml'),
    ],
    { cwd: eqlRoot, stdio: 'inherit' },
  )
}

function main() {
  // This script lives at the monorepo root (`scripts/`) because Changesets only
  // runs the ROOT `version` script — but every path it touches is inside the EQL
  // subtree, and `mise` needs the subtree's own `mise.toml`, which is not found
  // from the monorepo root. So resolve the EQL root explicitly rather than
  // treating the script's parent directory as the base.
  const stackRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
  const eqlRoot = join(stackRoot, 'packages/eql')

  const pkgPath = join(eqlRoot, 'packages/eql/package.json')
  const version = JSON.parse(readFileSync(pkgPath, 'utf8')).version
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error(`could not read a version from ${pkgPath}`)
  }

  const cargoPath = join(eqlRoot, 'crates/eql-bindings/Cargo.toml')
  writeFileSync(
    cargoPath,
    bumpCargoPackageVersion(readFileSync(cargoPath, 'utf8'), version),
  )

  // Before the SQL build, not after: this is cheap and offline, so a cargo that
  // cannot run should stop the release in seconds rather than after a full
  // eql-codegen compile.
  const workspaces = cargoLockWorkspaces(stackRoot)
  if (workspaces.length === 0) {
    throw new Error(
      `no Cargo.lock under ${stackRoot} records \`${LOCKED_CRATE}\` as a path dependency — ` +
        'the scan that finds the locks to refresh has stopped matching, so the bump above ' +
        'would leave every one of them stale.',
    )
  }
  for (const workspace of workspaces) {
    refreshCargoLock({ root: stackRoot, eqlRoot, workspace })
  }

  // Build the exact-version SQL and copy it (+ manifests) into both packages.
  execFileSync(
    'mise',
    ['run', 'release:prepare_bindings_assets', '--version', version],
    {
      cwd: eqlRoot,
      stdio: 'inherit',
    },
  )

  console.log(
    `synced EQL lockstep version ${version} to Cargo.toml, ` +
      `${workspaces.length} Cargo.lock (${workspaces.join(', ')}) + bundled SQL assets`,
  )
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main()
}
