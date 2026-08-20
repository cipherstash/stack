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
//      crate and the npm package — UNLESS the tree already carries those assets
//      at V, in which case step 4 is skipped. See `eqlLockstepSkew` for why.
//
// Step 3 is not decoration. Step 2 moves a version that `packages/protect-ffi`'s
// SEPARATE cargo workspace has pinned in its own lock, and nothing else updates
// it — `packages/eql`'s lock is refreshed as a side effect of step 4, that one
// by nothing at all. Since no command in this repo passes `--locked`, the stale
// lock is silently regenerated on every CI run and the committed file drifts
// further out on each bump. `scripts/__tests__/cargo-lock-freshness.test.mjs`
// fails a PR that carries the drift; step 3 is what stops producing it.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
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
 * NOT `--offline`, however tempting it looks. `eql-bindings` resolves from a
 * path, so the flag reads as free — but `cargo update -p X` does not update X
 * in isolation. It re-resolves the whole graph and rewrites a complete lock,
 * and offline that means every OTHER package has to be served from the local
 * registry cache; `packages/protect-ffi` has 167 of them. The release job has
 * no such cache — `jdx/mise-action` runs there with `cache: false`, installing
 * toolchains and populating nothing under `~/.cargo/registry`, and
 * `scripts/lint-no-workflow-caching.mjs` forbids a cache restore anywhere an
 * artifact is published. So `--offline` died on the first call with
 * `error: no matching package named \`chrono\` found`, taking `pnpm run version`
 * with it AFTER `changeset version` had rewritten every manifest and CHANGELOG.
 *
 * The two resolutions agree where both can run — verified byte-identical on the
 * 3.0.4 -> 3.0.5 bump, `windows-sys` edges included — so this is a change of
 * where the step works, not of what it produces. Asserted, with the CI
 * precondition it depends on, in scripts/__tests__/sync-lockstep-versions.test.mjs.
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
      '--package',
      LOCKED_CRATE,
      '--manifest-path',
      join(root, workspace, 'Cargo.toml'),
    ],
    { cwd: eqlRoot, stdio: 'inherit' },
  )
}

/**
 * The EQL subtree, repo-relative.
 *
 * The subtree root deliberately carries no `package.json`, so the npm package
 * is two levels down at `packages/eql/packages/eql` — see AGENTS.md, "Working
 * on EQL". Every path below is relative to THIS directory, matching how
 * `packages/eql/mise.toml`'s tasks address their own inputs.
 */
export const EQL_SUBTREE = 'packages/eql'

/** Subtree-relative path of the npm package `sync-lockstep-versions` reads V from. */
export const EQL_PACKAGE_JSON = 'packages/eql/package.json'

/** Subtree-relative path of the crate `bumpCargoPackageVersion` rewrites. */
export const EQL_CRATE_MANIFEST = 'crates/eql-bindings/Cargo.toml'

/**
 * Subtree-relative path of the TypeScript mirror of the release manifest.
 *
 * `prepare-bindings-assets.sh` writes it as a fourth copy of the same four
 * fields, and `@cipherstash/eql`'s `readVerifiedInstallSql()` checks the bundle
 * against it at runtime. `sync-generated.mjs --check` cannot see drift here:
 * its `renderReleaseManifest()` returns the file's existing contents verbatim
 * when the file exists, so the generated-output gate reproduces whatever is
 * there and passes.
 */
export const EQL_TS_MANIFEST = 'packages/eql/src/generated/release-manifest.ts'

/** The two SQL files a release manifest hashes, and the field each is hashed into. */
const HASHED_SQL = [
  ['cipherstash-encrypt.sql', 'installSqlSha256'],
  ['cipherstash-encrypt-uninstall.sql', 'uninstallSqlSha256'],
]

/** V, from the npm package that owns it. Throws rather than returning nothing. */
export function readEqlVersion(eqlRoot) {
  const path = join(eqlRoot, EQL_PACKAGE_JSON)
  const version = JSON.parse(readFileSync(path, 'utf8')).version
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error(`could not read a version from ${path}`)
  }
  return version
}

/**
 * Every `release-manifest.json` under the subtree, subtree-relative.
 *
 * DISCOVERED rather than listed, for `cargo_lock_workspaces`' reason: a copy
 * added by a future subtree pull is checked the day it lands. `SKIP_DIRS`
 * carries the load here — `dist/` holds tsup's copy of these same files and
 * `target/` holds cargo's, and neither is a committed artefact. `release/` is
 * excluded by construction rather than by name: it is the build intermediate
 * `tasks/build.sh` writes, it holds only the SQL, and every SQL path below is
 * derived as a manifest's SIBLING. A warm worktree's `release/` is routinely
 * weeks stale, so a scan that reached it would fail on a developer's machine
 * and pass in CI.
 */
export function eqlReleaseManifests(eqlRoot) {
  const found = []
  const walk = (abs) => {
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(join(abs, entry.name))
      } else if (entry.name === 'release-manifest.json') {
        found.push(
          relative(eqlRoot, join(abs, entry.name)).split(sep).join('/'),
        )
      }
    }
  }
  walk(eqlRoot)
  return found.sort()
}

/**
 * The release identity stamped INSIDE the install bundle, or `null`.
 *
 * `prepare-bindings-assets.sh` reads the same line with the same anchor before
 * it will write a manifest over the file. This is the property that survives
 * into the tree: the manifest is regenerated with the SQL and goes on agreeing
 * with it, so the stamp is the only field that still records which build
 * produced these bytes.
 */
export function sqlVersionStamp(sql) {
  const match = /^COMMENT ON SCHEMA eql_v3 IS '(.*)';$/m.exec(sql)
  return match ? match[1] : null
}

/** The four fields of `release-manifest.ts`, read without a TypeScript parser. */
function parseTsManifest(source) {
  const field = (name) =>
    new RegExp(`^\\s*${name}: '([^']*)',$`, 'm').exec(source)?.[1] ?? null
  return {
    eqlVersion: field('eqlVersion'),
    installSqlSha256: field('installSqlSha256'),
    uninstallSqlSha256: field('uninstallSqlSha256'),
  }
}

/**
 * Every way the EQL lockstep artefacts can disagree with the version the npm
 * package declares — as `{ checked, skew }`, both subtree-relative.
 *
 * ## Why this exists at all
 *
 * One version V ships as five artefacts, and until this function the SQL half
 * of that had no in-tree check. The Cargo half has one
 * (`cargo-lock-freshness.test.mjs`, chaining `Cargo.lock` -> `Cargo.toml`); the
 * SQL half was covered only by `release-gate.mjs`'s `FROZEN_ARTEFACT_DIGESTS`,
 * which compares against NPM rather than against this tree's own declared
 * version, and which the Phase-5 cutover deletes along with `FROZEN_PUBLISHERS`.
 * Nothing here is keyed to that map: this is a property of a lockstep release,
 * not of who publishes it, so it survives the cutover.
 *
 * ## The three disagreements, and why all three are needed
 *
 *   1. a manifest's `eqlVersion` is not V;
 *   2. a manifest's digest is not the sha256 of the file beside it;
 *   3. the install bundle's own `COMMENT ON SCHEMA eql_v3 IS '…'` stamp is not V.
 *
 * (2) is what the generator already guarantees, and it is satisfied by any
 * self-consistent pair — stale included. (1) is satisfied by a hand-edited
 * manifest. (3) is the one that actually happens: `mise run build --version X`
 * does NOT treat `--version` as a cache-key input (it is absent from
 * `tasks/build.sh`'s `#MISE sources`), so on unchanged SQL and Rust it is a
 * cache HIT that re-serves whatever version the previous build stamped, and
 * everything downstream copies those bytes verbatim under a manifest asserting
 * X. Every digest verifies. Only the stamp disagrees, and it is invisible to
 * both other checks.
 *
 * ## Why the crate manifest is in here too
 *
 * `cargo-lock-freshness.test.mjs` chains `Cargo.lock` -> `Cargo.toml` and stops
 * there. Nothing chained `Cargo.toml` -> `package.json`, so a bump interrupted
 * between steps 1 and 2 of this script leaves the crate a release behind with
 * every lock agreeing with it — internally consistent, and wrong.
 *
 * An empty scan THROWS. "No manifests found" and "every manifest agrees" are
 * the same value otherwise, and it is the reading that lets `main()` skip the
 * asset build below.
 */
export function eqlLockstepSkew({ eqlRoot, version }) {
  const checked = []
  const skew = []
  const manifests = eqlReleaseManifests(eqlRoot)
  if (manifests.length === 0) {
    throw new Error(
      `no release-manifest.json under ${eqlRoot} — the scan that finds the EQL lockstep ` +
        'artefacts has stopped matching, so "everything agrees" would be a report about ' +
        'nothing.',
    )
  }

  for (const manifestPath of manifests) {
    checked.push(manifestPath)
    const manifest = JSON.parse(
      readFileSync(join(eqlRoot, manifestPath), 'utf8'),
    )
    if (manifest.eqlVersion !== version) {
      skew.push(
        `${manifestPath}: eqlVersion '${manifest.eqlVersion}', but ${EQL_PACKAGE_JSON} declares '${version}'`,
      )
    }

    const dir = dirname(manifestPath)
    for (const [file, field] of HASHED_SQL) {
      const sqlPath = `${dir}/${file}`
      checked.push(sqlPath)
      const abs = join(eqlRoot, sqlPath)
      if (!existsSync(abs)) {
        skew.push(
          `${sqlPath}: missing, but ${manifestPath} hashes it as ${field}`,
        )
        continue
      }
      const bytes = readFileSync(abs)
      const digest = createHash('sha256').update(bytes).digest('hex')
      if (digest !== manifest[field]) {
        skew.push(
          `${sqlPath}: sha256 ${digest}, but ${manifestPath} records ${field} ${manifest[field]}`,
        )
      }
      // Only the install bundle carries a stamp; the uninstaller is four
      // statements with no version in it.
      if (field !== 'installSqlSha256') continue
      const stamped = sqlVersionStamp(bytes.toString('utf8'))
      if (stamped !== version) {
        skew.push(
          `${sqlPath}: stamped '${stamped}', but ${EQL_PACKAGE_JSON} declares '${version}'. ` +
            'This is the `mise run build` cache hit: the bundle is a previous release, ' +
            'the digests over it verify, and only the stamp says so.',
        )
      }
    }
  }

  // The TypeScript mirror, compared against the npm package's own manifest —
  // the one it is a copy of, and the one tsup ships beside it.
  checked.push(EQL_TS_MANIFEST)
  const tsAbs = join(eqlRoot, EQL_TS_MANIFEST)
  if (!existsSync(tsAbs)) {
    skew.push(`${EQL_TS_MANIFEST}: missing`)
  } else {
    const ts = parseTsManifest(readFileSync(tsAbs, 'utf8'))
    const jsonPath = 'packages/eql/sql/release-manifest.json'
    const json = existsSync(join(eqlRoot, jsonPath))
      ? JSON.parse(readFileSync(join(eqlRoot, jsonPath), 'utf8'))
      : {}
    if (ts.eqlVersion !== version) {
      skew.push(
        `${EQL_TS_MANIFEST}: eqlVersion '${ts.eqlVersion}', but ${EQL_PACKAGE_JSON} declares '${version}'`,
      )
    }
    for (const [, field] of HASHED_SQL) {
      if (ts[field] !== json[field]) {
        skew.push(
          `${EQL_TS_MANIFEST}: ${field} '${ts[field]}', but ${jsonPath} records '${json[field]}'`,
        )
      }
    }
  }

  // The crate manifest. Read with the same `[package]`-anchored match
  // `bumpCargoPackageVersion` writes through, so the two cannot disagree about
  // which line they mean.
  checked.push(EQL_CRATE_MANIFEST)
  const crateAbs = join(eqlRoot, EQL_CRATE_MANIFEST)
  if (!existsSync(crateAbs)) {
    skew.push(`${EQL_CRATE_MANIFEST}: missing`)
  } else {
    const section = readFileSync(crateAbs, 'utf8').match(
      /^\[package\]\n(?:(?!^\[).*\n)*/m,
    )
    const crateVersion = section
      ? (/^version = "([^"]*)"$/m.exec(section[0])?.[1] ?? null)
      : null
    if (crateVersion !== version) {
      skew.push(
        `${EQL_CRATE_MANIFEST}: [package] version '${crateVersion}', but ${EQL_PACKAGE_JSON} declares '${version}'`,
      )
    }
  }

  return { checked, skew }
}

/**
 * Step 4: put the SQL bundle and its manifests in the tree at `version` — by
 * rebuilding them, or by leaving alone the ones already there.
 *
 * ## Why "leave alone" is a case at all
 *
 * `prepare-bindings-assets.sh` rebuilds and OVERWRITES all four release
 * manifests plus both copies of the SQL every time it runs, and this script
 * runs on EVERY release, not just the ones that bump `@cipherstash/eql`. On a
 * release where the version is unchanged, that rewrite has no upside and one
 * specific downside: if the generated bytes differ from the committed ones for
 * any reason — and `packages/eql/mise.toml` pins `rust = { version = "latest" }`,
 * so the toolchain is not the same one from month to month — the Version
 * Packages commit carries a new digest under an unchanged version number.
 *
 * For `@cipherstash/eql` that is not a cosmetic diff. It is a FROZEN publisher:
 * the version cannot be released from here, so the tree is not proposing those
 * bytes, it is asserting they are already on npm under that number. The next
 * `release-gate.mjs` run compares the two and fires `frozen-bytes-skew`, which
 * exits non-zero, fails the `gate` job, and skips `release` entirely — the
 * whole release, for every package, blocked by a regenerated artefact for a
 * version nobody was releasing. Fail-closed, so not a correctness hole; a
 * release-stopper that arrives AFTER `changeset version` has rewritten every
 * manifest and CHANGELOG in the tree, which is the worst moment available.
 *
 * ## Why skipping is not "leaving it stale"
 *
 * The skip is conditional on `eqlLockstepSkew` finding NOTHING: every manifest
 * at `version`, every digest equal to the sha256 of the file beside it, and the
 * install bundle's own in-SQL stamp at `version` too. A bump moves
 * `package.json` before this runs, so a real version change always disagrees
 * and always rebuilds. What the skip declines is the no-op — and for the one
 * case where in-tree SQL *source* changed without a version bump, declining is
 * the correct answer rather than a missed one: regenerating there would
 * republish different bytes under a released number, which is precisely what
 * the gate refuses. That change needs a changeset, and the changeset is what
 * brings the rebuild back.
 *
 * `run` and `log` are injected for the unit tests: what matters is whether the
 * build was invoked and with what argv, and asserting that must not require a
 * Rust toolchain on the machine running `test:scripts`.
 */
export function prepareBindingAssets({
  eqlRoot,
  version,
  run = execFileSync,
  log = console.log,
}) {
  const { skew } = eqlLockstepSkew({ eqlRoot, version })
  if (skew.length === 0) {
    log(
      `EQL binding assets are already prepared for ${version} — skipping ` +
        '`mise run release:prepare_bindings_assets`. Rebuilding an unchanged version ' +
        'can only introduce a digest the registry does not carry.',
    )
    return { action: 'skipped', skew }
  }

  for (const reason of skew) log(`  rebuilding: ${reason}`)
  run(
    'mise',
    ['run', 'release:prepare_bindings_assets', '--version', version],
    {
      cwd: eqlRoot,
      stdio: 'inherit',
    },
  )

  // The generator's own `--force` + stamp check covers the build; this covers
  // the COPY. Four manifests and four SQL files are written by six lines of
  // shell, and a partial run leaves a tree that verifies in some directories
  // and not others. Checking after is what turns that into a failed release
  // rather than a committed one.
  const after = eqlLockstepSkew({ eqlRoot, version })
  if (after.skew.length > 0) {
    throw new Error(
      `\`mise run release:prepare_bindings_assets --version ${version}\` ran, and the EQL ` +
        'lockstep artefacts still disagree:\n' +
        after.skew.map((line) => `  ${line}`).join('\n'),
    )
  }
  return { action: 'rebuilt', skew }
}

function main() {
  // This script lives at the monorepo root (`scripts/`) because Changesets only
  // runs the ROOT `version` script — but every path it touches is inside the EQL
  // subtree, and `mise` needs the subtree's own `mise.toml`, which is not found
  // from the monorepo root. So resolve the EQL root explicitly rather than
  // treating the script's parent directory as the base.
  const stackRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
  const eqlRoot = join(stackRoot, 'packages/eql')

  const version = readEqlVersion(eqlRoot)

  const cargoPath = join(eqlRoot, 'crates/eql-bindings/Cargo.toml')
  writeFileSync(
    cargoPath,
    bumpCargoPackageVersion(readFileSync(cargoPath, 'utf8'), version),
  )

  // Before the SQL build, not after: this is cheap, so a cargo that cannot run
  // should stop the release in seconds rather than after a full eql-codegen
  // compile.
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

  // Build the exact-version SQL and copy it (+ manifests) into both packages —
  // unless the tree already carries them at this version.
  const assets = prepareBindingAssets({ eqlRoot, version })

  console.log(
    `synced EQL lockstep version ${version} to Cargo.toml, ` +
      `${workspaces.length} Cargo.lock (${workspaces.join(', ')}) + bundled SQL assets ` +
      `(${assets.action})`,
  )
}

// `fileURLToPath`, not `` `file://${process.argv[1]}` ``: the URL is
// percent-encoded and the argv path is not, so the template form is false from
// any checkout path containing a space — and this script's caller is
// `changeset version && node scripts/sync-lockstep-versions.mjs`, where a
// silent exit 0 reports a completed lockstep bump that never happened.
// `scripts/__tests__/script-main-guards.test.mjs` holds this form repo-wide.
if (process.argv[1] === fileURLToPath(import.meta.url)) main()
