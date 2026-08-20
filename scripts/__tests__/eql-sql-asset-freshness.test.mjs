import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  EQL_SUBTREE,
  eqlLockstepSkew,
  readEqlVersion,
} from '../sync-lockstep-versions.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * One version V, five artefacts — and this is the half of it nothing was
 * checking.
 *
 * ## What the tree claims, and who checks it
 *
 * `@cipherstash/eql`'s `package.json` version is V (owned by `changeset
 * version`). `scripts/sync-lockstep-versions.mjs` carries V to the crate
 * manifest and, via `mise run release:prepare_bindings_assets`, to the SQL
 * bundle — which is stamped with V *inside the SQL text* and hashed into three
 * release manifests: the npm package's `sql/release-manifest.json`, the crate's
 * copy, and `src/generated/release-manifest.ts`.
 *
 * The Cargo half of that propagation has a guard
 * (`cargo-lock-freshness.test.mjs`, which chains `Cargo.lock` -> `Cargo.toml`).
 * The SQL half had none. Before this file, `grep -rn 'eqlVersion' scripts/`
 * matched two lines, both inside `release-gate.mjs`'s `FROZEN_ARTEFACT_DIGESTS`
 * — and that check compares against **npm**, not against the version this tree
 * declares, and is keyed to `FROZEN_PUBLISHERS`, which the Phase-5 cutover
 * DELETES (`frozen-publisher-docs.test.mjs` enforces the paired deletion). So
 * the one thing covering the SQL assets was scheduled for removal.
 *
 * This file is deliberately NOT keyed to `FROZEN_PUBLISHERS`. It compares the
 * tree against itself, which is a property of a lockstep release rather than a
 * property of who publishes it, so it survives the cutover untouched.
 *
 * ## Why the stamp is the thing that lags
 *
 * `mise run build --version X` does not treat `--version` as a cache-key input
 * — it is absent from `tasks/build.sh`'s `#MISE sources`. On unchanged SQL and
 * Rust that is a cache HIT which re-serves whatever version the PREVIOUS build
 * stamped, and everything downstream then copies those bytes verbatim under a
 * manifest asserting the requested version. The digests still verify; the
 * bundle ships stamped one version while the manifest, the crate and the npm
 * package all claim another. `prepare-bindings-assets.sh` passes `--force` and
 * re-greps the stamp for exactly this reason, but that is a check inside the
 * generator: it says nothing about the bytes sitting in the tree right now,
 * which is what `stash eql install` actually reads.
 *
 * ## The three properties, and why all three are needed
 *
 *   1. every manifest's `eqlVersion` equals the npm package's `version`;
 *   2. every manifest's digests equal the sha256 of the SQL beside it;
 *   3. the install SQL's own `COMMENT ON SCHEMA eql_v3 IS '…'` stamp equals V.
 *
 * (2) alone is what the generator already guarantees and it is satisfied by any
 * self-consistent pair, stale or not. (1) alone is satisfied by a hand-edited
 * manifest. (3) is the one the cache hit breaks, and it is invisible to both of
 * the others.
 *
 * The predicate itself lives in `sync-lockstep-versions.mjs` rather than here,
 * because the release hook needs the same answer — see FINDING 2 in that file's
 * `main()`. One implementation, two callers: a PR-time guard and a release-time
 * decision that must not disagree with it.
 */

const EQL_ROOT = join(REPO_ROOT, EQL_SUBTREE)
const VERSION = readEqlVersion(EQL_ROOT)
const { checked, skew } = eqlLockstepSkew({
  eqlRoot: EQL_ROOT,
  version: VERSION,
})

describe('the EQL lockstep artefacts all declare one version', () => {
  it('reads a version to compare against', () => {
    // The floor. `readEqlVersion` throws rather than returning undefined, but a
    // version of `''` or `'DEV'` would compare equal to a manifest carrying the
    // same placeholder and turn the whole file green over a broken tree.
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/)
  })

  it('found the artefacts it is checking', () => {
    // Discovery over the subtree means a walk that stops matching — a rename, a
    // new skipped directory, a subtree pull that moves `sql/` — turns every
    // assertion below into a comparison over an empty list. Name the two
    // committed asset directories and the TypeScript mirror explicitly: those
    // are the three that ship, and each is written by a different line of
    // `prepare-bindings-assets.sh`.
    expect(checked).toContain('packages/eql/sql/release-manifest.json')
    expect(checked).toContain('crates/eql-bindings/sql/release-manifest.json')
    expect(checked).toContain('packages/eql/src/generated/release-manifest.ts')
    expect(checked).toContain('crates/eql-bindings/Cargo.toml')
    // Both SQL bundles, under both manifests — the files whose bytes are what a
    // customer's database actually receives.
    expect(
      checked.filter((path) => path.endsWith('cipherstash-encrypt.sql')),
    ).toHaveLength(2)
    expect(
      checked.filter((path) =>
        path.endsWith('cipherstash-encrypt-uninstall.sql'),
      ),
    ).toHaveLength(2)
  })

  it('does not reach into build output', () => {
    // `packages/eql/release/` is an untracked, gitignored intermediate that
    // `mise run build` leaves behind, and on a warm worktree it is routinely
    // STALE — the copy in this repo hashed the pre-`ste_vec_contains` bundle,
    // weeks behind the committed assets. `packages/eql/packages/eql/dist/sql/`
    // is tsup's copy of the same files. Either one inside the scan makes this
    // suite fail on a developer's machine and pass in CI, which is the shape of
    // a guard everybody learns to ignore.
    expect(
      checked.filter(
        (path) =>
          path.startsWith('release/') ||
          path.includes('/dist/') ||
          path.includes('/node_modules/'),
      ),
    ).toEqual([])
  })

  it('agrees on the version, the digests and the SQL stamp', () => {
    // THE DEFECT. Any of three disagreements lands here: a manifest naming a
    // different version, a digest that is not the sha256 of the file beside it,
    // or an install bundle whose in-SQL stamp lags the version the manifest
    // asserts over it — the last being what a `mise run build` cache hit
    // produces, with every digest still verifying.
    expect(
      skew,
      "The EQL lockstep artefacts disagree with @cipherstash/eql's package.json version. " +
        'Regenerate them with `mise run release:prepare_bindings_assets --version ' +
        `${VERSION}` +
        '` from packages/eql (mise reads its config from the current directory, so it must ' +
        'be run from the subtree root). If the SQL genuinely changed, that is a version bump, ' +
        'not a regeneration: @cipherstash/eql is a frozen publisher and republishing different ' +
        "bytes under a released number is what `release-gate.mjs`'s frozen-bytes-skew check " +
        'refuses.',
    ).toEqual([])
  })
})

/**
 * MUTATION PROOF.
 *
 * Everything above is an assertion that a list is empty, over a tree that is
 * currently consistent — the exact shape that passes when the scan has quietly
 * stopped looking. These build a subtree that is wrong in each of the three
 * ways and assert the predicate says so, naming the file.
 *
 * Built rather than copied: the real install bundle is 2.6 MB and the property
 * under test is arithmetic over bytes, not the bytes themselves.
 */
describe('eqlLockstepSkew catches each way the assets can lag', () => {
  const sha = (text) => createHash('sha256').update(text).digest('hex')

  /**
   * A minimal EQL subtree at `version`, with `overrides` applied on top.
   *
   * `install`/`uninstall` are the SQL bodies; the manifests are written to
   * agree with them unless an override says otherwise, so each test below
   * introduces exactly one disagreement.
   */
  const subtree = ({
    version = '3.1.0',
    install = `SELECT 1;\nCOMMENT ON SCHEMA eql_v3 IS '${version}';\n`,
    uninstall = 'DROP SCHEMA eql_v3 CASCADE;\n',
    manifestVersion = version,
    installDigest = null,
    packageVersion = version,
    crateVersion = version,
  } = {}) => {
    const root = mkdtempSync(join(tmpdir(), 'eql-lockstep-'))
    const manifest = {
      eqlVersion: manifestVersion,
      schemaVersion: 3,
      installSqlSha256: installDigest ?? sha(install),
      uninstallSqlSha256: sha(uninstall),
    }
    for (const dir of ['packages/eql/sql', 'crates/eql-bindings/sql']) {
      mkdirSync(join(root, dir), { recursive: true })
      writeFileSync(join(root, dir, 'cipherstash-encrypt.sql'), install)
      writeFileSync(
        join(root, dir, 'cipherstash-encrypt-uninstall.sql'),
        uninstall,
      )
      writeFileSync(
        join(root, dir, 'release-manifest.json'),
        `${JSON.stringify(manifest, null, 2)}\n`,
      )
    }
    mkdirSync(join(root, 'packages/eql/src/generated'), { recursive: true })
    writeFileSync(
      join(root, 'packages/eql/src/generated/release-manifest.ts'),
      'export const releaseManifest = {\n' +
        `  eqlVersion: '${manifest.eqlVersion}',\n` +
        '  schemaVersion: 3,\n' +
        `  installSqlSha256: '${manifest.installSqlSha256}',\n` +
        `  uninstallSqlSha256: '${manifest.uninstallSqlSha256}',\n` +
        '} as const\n',
    )
    writeFileSync(
      join(root, 'packages/eql/package.json'),
      `${JSON.stringify({ name: '@cipherstash/eql', version: packageVersion }, null, 2)}\n`,
    )
    writeFileSync(
      join(root, 'crates/eql-bindings/Cargo.toml'),
      `[package]\nname = "eql-bindings"\nversion = "${crateVersion}"\n\n[dependencies]\nserde = "1"\n`,
    )
    return root
  }

  /** Run the predicate over a scratch subtree, then delete it. */
  const skewOf = (options = {}) => {
    const root = subtree(options)
    try {
      return eqlLockstepSkew({
        eqlRoot: root,
        version: readEqlVersion(root),
      })
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }

  it('is silent on a consistent subtree', () => {
    // The other half of every mutation check: this must not be a guard that
    // always fires. Same builder, no override.
    const { checked, skew } = skewOf()
    expect(skew).toEqual([])
    expect(checked.length).toBeGreaterThan(0)
  })

  it('catches the SQL stamp lagging the package version', () => {
    // THE CACHE-HIT FAILURE, exactly as `mise run build --version X` produces
    // it: the bundle is byte-for-byte the PREVIOUS release, its digests are
    // recomputed over those bytes so every manifest verifies, and only the
    // stamp inside the SQL still says where it came from.
    const stale = "SELECT 1;\nCOMMENT ON SCHEMA eql_v3 IS '3.0.5';\n"
    const { skew } = skewOf({ version: '3.1.0', install: stale })
    expect(skew.join('\n')).toMatch(
      /packages\/eql\/sql\/cipherstash-encrypt\.sql.*stamped '3\.0\.5'.*3\.1\.0/,
    )
    expect(skew.join('\n')).toMatch(
      /crates\/eql-bindings\/sql\/cipherstash-encrypt\.sql.*stamped '3\.0\.5'/,
    )
  })

  it('catches a manifest naming a version the package does not', () => {
    const { skew } = skewOf({ version: '3.1.0', manifestVersion: '3.0.5' })
    expect(skew.join('\n')).toMatch(/eqlVersion.*3\.0\.5.*3\.1\.0/)
  })

  it('catches a digest that is not the sha256 of the file beside it', () => {
    // The hand-edited case, and the partial-copy case: a manifest asserting
    // bytes that are not there. `packages/cli`'s installer reads the SQL
    // verbatim, so nothing downstream re-checks this.
    const { skew } = skewOf({ installDigest: 'deadbeef' })
    expect(skew.join('\n')).toMatch(
      /cipherstash-encrypt\.sql.*deadbeef|deadbeef.*cipherstash-encrypt\.sql/,
    )
  })

  it('catches the crate falling behind the npm package', () => {
    // The other end of the same bump. `cargo-lock-freshness.test.mjs` chains
    // Cargo.lock -> Cargo.toml; nothing chained Cargo.toml -> package.json, so
    // a bump that stopped before step 2 of the hook left the crate a release
    // behind with both locks agreeing with it.
    const { skew } = skewOf({ version: '3.1.0', crateVersion: '3.0.5' })
    expect(skew.join('\n')).toMatch(/Cargo\.toml.*3\.0\.5.*3\.1\.0/)
  })

  it('catches the TypeScript mirror falling behind its JSON', () => {
    // `src/generated/release-manifest.ts` is what `@cipherstash/eql`'s
    // `readVerifiedInstallSql()` checks the bundle against at runtime, and
    // `sync-generated.mjs --check` cannot catch drift here: its
    // `renderReleaseManifest()` PRESERVES whatever the file already contains,
    // so the generated-output gate reproduces the stale value and passes.
    const root = subtree()
    try {
      writeFileSync(
        join(root, 'packages/eql/src/generated/release-manifest.ts'),
        "export const releaseManifest = {\n  eqlVersion: '3.0.5',\n  schemaVersion: 3,\n" +
          "  installSqlSha256: 'deadbeef',\n  uninstallSqlSha256: 'deadbeef',\n} as const\n",
      )
      const { skew } = eqlLockstepSkew({
        eqlRoot: root,
        version: readEqlVersion(root),
      })
      expect(skew.join('\n')).toMatch(/release-manifest\.ts/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('reports a missing artefact rather than skipping it', () => {
    // A manifest whose SQL is absent must not read as "nothing to compare".
    // That is the same silence as a scan that stopped matching, and it is
    // reachable by an interrupted copy — `prepare-bindings-assets.sh` writes
    // three files per directory, not one.
    const root = subtree()
    try {
      rmSync(join(root, 'packages/eql/sql/cipherstash-encrypt.sql'))
      const { skew } = eqlLockstepSkew({
        eqlRoot: root,
        version: readEqlVersion(root),
      })
      expect(skew.join('\n')).toMatch(/missing/i)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('throws when the scan finds no manifests at all', () => {
    // An empty subtree is indistinguishable from a consistent one by the
    // result, and it is the reading that lets the release hook skip the asset
    // build. Loud, in the shape of `workspacePackagePatterns`' empty throw.
    const root = mkdtempSync(join(tmpdir(), 'eql-lockstep-empty-'))
    try {
      expect(() =>
        eqlLockstepSkew({ eqlRoot: root, version: '3.1.0' }),
      ).toThrow(/release-manifest\.json/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
