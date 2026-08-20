/**
 * Integrity check for the EQL install bundle the CLI executes.
 *
 * `tsup.config.ts` keeps `@cipherstash/eql` external so `readInstallSql()`
 * resolves the *installed* package at runtime — the copy in the user's
 * `node_modules`, on their disk, not bytes baked into the `stash` tarball.
 * That is the right design (one bundle, pinned by the dependency graph), but
 * it means everything `stash eql install` executes against a customer database
 * arrives through a bare `existsSync` + `readFileSync` with nothing asserting
 * it is the bundle the resolved release attests to.
 *
 * The failure mode is silent by construction. A tree declaring `3.0.5` whose
 * install bundle hashed `7ad9c9f8…` against npm's published `accde0030…` is
 * not hypothetical — it is what upstream restoring the deprecated
 * `ste_vec_contains` aliases produced, and `stash eql install` would have
 * created functions the version it reports does not define, then said
 * "EQL extensions installed." Nothing downstream can notice: `eql_v3.version()`
 * returns the manifest's number either way.
 *
 * `@cipherstash/eql` already ships the answer — `releaseManifest`'s
 * `installSqlSha256`, generated from the same tsup run that copies the SQL into
 * `dist/sql/`. It was imported by `verify.ts` for its `eqlVersion` alone.
 * `packages/stack-prisma` has verified against it since the v3 migrations
 * landed ({@link https://github.com/cipherstash/stack} —
 * `src/migration/eql-bundle-v3.ts`'s `readVerifiedInstallSql`); this is the
 * same check on the path that actually reaches customer databases.
 */
import { createHash } from 'node:crypto'
import { installSqlPath, releaseManifest } from '@cipherstash/eql/sql'

/**
 * Where the bytes came from, for the error message. Guarded because this runs
 * only on the refusal path: an older resolved `@cipherstash/eql` without the
 * export would otherwise turn a security refusal into a bare `TypeError`,
 * losing both digests along with the path.
 */
function resolvedBundlePath(): string {
  try {
    return typeof installSqlPath === 'function'
      ? installSqlPath()
      : '<unknown: @cipherstash/eql does not export installSqlPath()>'
  } catch {
    return '<unknown: @cipherstash/eql/sql installSqlPath() threw>'
  }
}

/**
 * Verify `sql` is byte-for-byte the install bundle the resolved
 * `@cipherstash/eql` release attests to, returning it unchanged on success.
 *
 * **Fail-closed.** A warning would be worth nothing here: the operator sees it
 * after the SQL has already run, and the only safe response to "these are not
 * the bytes the pinned release attests to" is not to execute them.
 *
 * Pure — exported separately from {@link loadBundledEqlSql} so the refusal path
 * is testable without tampering with the real package files.
 */
export function assertBundledEqlSqlDigest(sql: string): string {
  const digest = createHash('sha256').update(sql).digest('hex')
  if (digest === releaseManifest.installSqlSha256) return sql
  throw new Error(
    `EQL v3 install SQL failed digest verification — refusing to run it.\n` +
      `  expected sha256: ${releaseManifest.installSqlSha256} (releaseManifest.installSqlSha256 for eql-${releaseManifest.eqlVersion})\n` +
      `  actual sha256:   ${digest}\n` +
      `  read from:       ${resolvedBundlePath()}\n` +
      'These are not the bytes the resolved `@cipherstash/eql` release attests to, so installing them would leave the database carrying SQL that ' +
      `eql-${releaseManifest.eqlVersion} does not define — while still reporting that version. ` +
      "Reinstall dependencies (`pnpm install --frozen-lockfile`, or your package manager's equivalent); if the mismatch survives a clean install, the installed package is corrupt or has been tampered with — do not proceed.",
  )
}
