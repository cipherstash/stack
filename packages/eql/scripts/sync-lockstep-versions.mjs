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
// It:
//   1. reads V from packages/eql/package.json,
//   2. sets crates/eql-bindings/Cargo.toml [package] version = V,
//   3. runs `mise run release:prepare_bindings_assets --version V`, which builds
//      the exact-version SQL and writes it (+ release manifests) into both the
//      crate and the npm package.

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import process from 'node:process'

// Set the `[package]` section's version in Cargo.toml text. Anchored to the
// section header rather than "first `version = ...` line in the file" so a
// dependency table that happens to carry a column-0 `version = "..."` line
// (e.g. `[dependencies.foo]` long form) can never be rewritten by mistake.
// Exported for scripts/sync-lockstep-versions.test.mjs.
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

function main() {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

  const pkgPath = join(repoRoot, 'packages/eql/package.json')
  const version = JSON.parse(readFileSync(pkgPath, 'utf8')).version
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error(`could not read a version from ${pkgPath}`)
  }

  const cargoPath = join(repoRoot, 'crates/eql-bindings/Cargo.toml')
  writeFileSync(cargoPath, bumpCargoPackageVersion(readFileSync(cargoPath, 'utf8'), version))

  // Build the exact-version SQL and copy it (+ manifests) into both packages.
  execFileSync('mise', ['run', 'release:prepare_bindings_assets', '--version', version], {
    cwd: repoRoot,
    stdio: 'inherit',
  })

  console.log(`synced EQL lockstep version ${version} to Cargo.toml + bundled SQL assets`)
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main()
}
