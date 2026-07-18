/**
 * CipherStash EQL v3 install SQL, sourced from `@cipherstash/eql/sql` — the
 * same source the stack install script (`packages/stack/scripts/install-eql-v3.ts`
 * / `installEqlV3IfNeeded`) uses. `readInstallSql()` returns the full bundle
 * that creates the `public.eql_v3_*` domains and the `eql_v3.*` operator
 * functions; `releaseManifest.eqlVersion` identifies the pinned release.
 *
 * The SQL is read at migration EMIT time and baked into the v3 baseline
 * migration's `ops.json`, so `@cipherstash/eql` stays a devDependency of this
 * package (not a runtime dependency of the published artefact). Bumping the
 * pinned `@cipherstash/eql` version requires re-running the maintainer emit
 * loop for `migrations/20260601T0100_install_eql_v3_bundle/` (see that
 * migration's header comment) and re-running `test/descriptor.test.ts` /
 * `test/v3/migration-v3.test.ts`.
 *
 * Hash impact: like the v2 bundle (see `./eql-bundle.ts`), the SQL lives in
 * the migration op's `execute[]`, NOT in `contract.json` — the v3 bundle
 * declares no contract-space storage, so the edge is invariant-only and
 * `headRef.hash` does not move.
 */
export { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
