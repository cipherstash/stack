/**
 * CipherStash EQL v3 install SQL, sourced from `@cipherstash/eql/sql` at
 * RUNTIME — the same source the stack install script (`installEqlV3IfNeeded`)
 * and the CLI installer (`readV3InstallSql`) use. `readInstallSql()` returns
 * the full bundle that creates the `public.eql_v3_*` domains and the `eql_v3.*`
 * operator functions; `releaseManifest.eqlVersion` identifies the pinned
 * release.
 *
 * ## Runtime-sourced, NOT baked
 *
 * The v3 baseline migration does **not** embed the ~1.7 MB install SQL in its
 * `ops.json`. The committed op carries {@link RUNTIME_EQL_SQL_SENTINEL}, and
 * `src/exports/control.ts` swaps in `readInstallSql()` from the INSTALLED
 * `@cipherstash/eql` when it builds the descriptor (see {@link withRuntimeEqlSql}).
 * So `@cipherstash/eql` is a runtime dependency, and a patch/minor bump flows
 * through npm resolution — no re-emit of the migration, no re-release of this
 * package. (Baking it in coupled every EQL upgrade to a prisma-next release.)
 *
 * Why this is sound: the v3 baseline is an INVARIANT-ONLY self-edge
 * (`from === to`; the bundle declares no contract-space storage — unlike the v2
 * bundle's `eql_v2_configuration`). The install SQL therefore never contributes
 * to the contract-space hash, and `contractSpaceFromJson` passes the ops through
 * with no integrity check on their contents (`verifyMigrationHash` runs only on
 * the disk read path for the user's own repo, never on the in-memory extension
 * descriptor). Swapping the SQL at descriptor-construction time is invisible to
 * the planner, which routes purely on the `cipherstash:install-eql-v3-bundle-v1`
 * invariant.
 */
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'

export { readInstallSql, releaseManifest }

/** The install op's `id` in the v3 baseline `ops.json`. */
export const V3_INSTALL_OP_ID = 'cipherstash.install-eql-v3-bundle'

/**
 * Placeholder the committed v3 baseline op carries in `execute[].sql` in place
 * of the baked install SQL. It is replaced at runtime by {@link withRuntimeEqlSql};
 * if it ever reached a database directly it is an inert SQL comment.
 */
export const RUNTIME_EQL_SQL_SENTINEL =
  '-- EQL v3 install SQL is injected at runtime from @cipherstash/eql — see packages/prisma-next/src/migration/eql-bundle-v3.ts'

type OpLike = {
  readonly id?: unknown
  readonly execute?: ReadonlyArray<{
    readonly description?: unknown
    readonly sql?: unknown
  }>
}

/**
 * Return `ops` with the v3 install op's placeholder SQL replaced by the install
 * SQL from the installed `@cipherstash/eql`. Every other op passes through
 * untouched. Called by the descriptor in `control.ts` so the applied SQL always
 * matches the resolved `@cipherstash/eql` version, not a baked snapshot.
 */
export function withRuntimeEqlSql<T extends OpLike>(ops: readonly T[]): T[] {
  const sql = readInstallSql()
  return ops.map((op) =>
    op.id === V3_INSTALL_OP_ID
      ? {
          ...op,
          execute: [
            {
              description: String(op.execute?.[0]?.description ?? ''),
              sql,
            },
          ],
        }
      : op,
  )
}
