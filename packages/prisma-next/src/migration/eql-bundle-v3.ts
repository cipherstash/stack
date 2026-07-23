/**
 * CipherStash EQL v3 install SQL, sourced from `@cipherstash/eql/sql` at
 * MIGRATION EMIT TIME — the same source the stack install script
 * (`installEqlV3IfNeeded`) and the CLI installer (`readV3InstallSql`) use.
 * `readVerifiedInstallSql()` returns the full bundle that creates the
 * `public.eql_v3_*` domains and the `eql_v3.*` operator functions, after
 * verifying it byte-for-byte against the release manifest's
 * `installSqlSha256`; `releaseManifest.eqlVersion` identifies the pinned
 * release.
 *
 * ## Baked at emit, verified by digest — NOT injected at runtime
 *
 * The v3 migration `ops.json` artefacts embed the full install SQL, written
 * by each migration's self-emit script (`pnpm exec tsx
 * migrations/<dirName>/migration.ts`). This is deliberate, and it follows
 * from two framework invariants that a runtime-injection design (the
 * previous sentinel scheme) violated:
 *
 *   1. **Migration packages are immutable by dirName.** The CLI's
 *      contract-space seed phase materialises descriptor-shipped packages
 *      into the user's `migrations/<spaceId>/` only when missing — existing
 *      directories are never rewritten. Injecting the installed
 *      `@cipherstash/eql`'s SQL at descriptor build (and recomputing the
 *      migration hash from it) changed the package's content-addressed
 *      identity behind an existing dirName on every EQL bump, so every
 *      consumer repo's vendored copy drifted out of the graph
 *      (PN-MIG-5002) the moment the pinned EQL version moved.
 *
 *   2. **Apply runs from disk, without the descriptor.**
 *      `computeExtensionSpaceApplyPath` reads only on-disk artefacts —
 *      `db init` / `db update` must work with no extension descriptor
 *      module present. Consumers therefore always executed the SQL baked
 *      into their vendored `ops.json`; the sentinel never reached a
 *      database through the framework's own apply path. "Runtime-sourced"
 *      only ever described this repo, not the artefact consumers run.
 *
 * Baking at emit gives one content-addressed identity everywhere: the
 * migration hash covers the actual SQL, the same bytes flow from this
 * repo's git history through the npm tarball into the consumer's vendored
 * copy, `verifyMigrationHash` re-checks them on every disk read, and the
 * DB ledger records the hash of exactly what was executed.
 *
 * ## Provenance: the SQL must come from `@cipherstash/eql`
 *
 * The emitted SQL is a build artefact of the pinned `@cipherstash/eql`
 * release, never hand-maintained. Two enforcement points keep that true:
 *
 *   - `readVerifiedInstallSql()` refuses to emit SQL whose sha256 does not
 *     match the installed package's `releaseManifest.installSqlSha256`.
 *   - `test/v3/migration-v3.test.ts` recomputes the digest of the SQL
 *     embedded in each committed `ops.json` and asserts it equals the
 *     installed manifest's digest, so CI fails if the committed artefact
 *     and the pinned `@cipherstash/eql` dependency ever skew (e.g. a
 *     version bump without a re-emit, or a hand-edit of the artefact).
 *
 * Bumping the pinned EQL version means: bump the dependency, add a NEW
 * upgrade migration directory carrying a fresh invariant (see
 * `20260720T0000_upgrade_eql_v3_3_0_2` — the append-only upgrade-edge
 * pattern), and re-run the self-emit. Existing migration directories are
 * never re-emitted; their bytes are already in consumers' repos.
 */
import { createHash } from 'node:crypto'
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'

// Re-exported for the live-test helpers, which read the same install SQL to
// set up their databases (`test/live/helpers/eql-v3.ts`,
// `migration-apply-live-pg`).
export { readInstallSql, releaseManifest }

/**
 * Verify that `sql` is byte-for-byte the install bundle the installed
 * `@cipherstash/eql` release attests to, returning it unchanged on success.
 *
 * Pure digest check, exported separately from {@link readVerifiedInstallSql}
 * so tests can exercise the refusal path without tampering with the real
 * package files.
 */
export function assertInstallSqlDigest(sql: string): string {
  const digest = createHash('sha256').update(sql).digest('hex')
  if (digest !== releaseManifest.installSqlSha256) {
    throw new Error(
      `EQL v3 install SQL failed digest verification: sha256 ${digest} does not match ` +
        `releaseManifest.installSqlSha256 ${releaseManifest.installSqlSha256} for eql-${releaseManifest.eqlVersion}. ` +
        'The SQL is not the bundle the installed `@cipherstash/eql` release attests to — refusing to use it. ' +
        'Reinstall dependencies; if the mismatch persists, the installed package is corrupt or tampered.',
    )
  }
  return sql
}

/**
 * Read the EQL v3 install SQL from the installed `@cipherstash/eql` and
 * verify it against the release manifest's digest. This is the ONLY
 * sanctioned source for the SQL embedded in the migration `ops.json`
 * artefacts — the migration self-emit scripts call it, so an artefact can
 * never be emitted from bytes the pinned release does not attest to.
 *
 * Turns a missing/broken package into an actionable error instead of a raw
 * `readFileSync` failure. Mirrors the CLI's `readV3InstallSql`.
 */
export function readVerifiedInstallSql(): string {
  let sql: string
  try {
    sql = readInstallSql()
  } catch (cause) {
    throw new Error(
      'Failed to read the EQL v3 install SQL from `@cipherstash/eql`. Reinstall dependencies — the package ships the bundle in `dist/sql/`.',
      { cause },
    )
  }
  return assertInstallSqlDigest(sql)
}
