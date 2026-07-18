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
 * `src/exports/control.ts` swaps in `readInstallSql()` from the installed
 * `@cipherstash/eql` when it builds the descriptor (see {@link withRuntimeEqlSql}).
 * `@cipherstash/eql` is therefore a runtime dependency, pinned exact (`3.0.0`)
 * to match the version `@cipherstash/stack` encodes its v3 domain TYPES against
 * — the two must move together, so this is a coordinated bump, not a float.
 *
 * The win over baking: upgrading the pinned `@cipherstash/eql` no longer means
 * re-emitting the 1.7 MB `ops.json` (which coupled every EQL bump to a manual
 * re-emit loop) — it is a one-line version bump plus a rebuild.
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

export { releaseManifest }

/**
 * Placeholder the committed v3 baseline op carries in `execute[].sql` in place
 * of the baked install SQL. {@link withRuntimeEqlSql} swaps it for the real
 * bundle at descriptor-build time; if it ever reached a database directly it is
 * an inert SQL comment. It is ALSO the join key the injector matches on — the
 * exact string the committed `ops.json` carries — so injection targets exactly
 * the placeholder and is immune to op-id / label drift.
 */
export const RUNTIME_EQL_SQL_SENTINEL =
  '-- EQL v3 install SQL is injected at runtime from @cipherstash/eql — see packages/prisma-next/src/migration/eql-bundle-v3.ts'

/**
 * Read the EQL v3 install SQL from the installed `@cipherstash/eql`, turning a
 * missing/broken package into an actionable error instead of a raw
 * `readFileSync` failure at descriptor-import time (this runs whenever any
 * control-plane consumer imports the descriptor). Mirrors the CLI's
 * `readV3InstallSql`.
 */
function readV3InstallSql(): string {
  try {
    return readInstallSql()
  } catch (cause) {
    throw new Error(
      'Failed to read the EQL v3 install SQL from `@cipherstash/eql`. Reinstall dependencies — the package ships the bundle in `dist/sql/`.',
      { cause },
    )
  }
}

type ExecuteStep = { readonly sql?: unknown }
type OpLike = { readonly execute?: ReadonlyArray<ExecuteStep> }

/**
 * Return `ops` with every placeholder install-SQL step ({@link
 * RUNTIME_EQL_SQL_SENTINEL}) replaced by the install SQL from the installed
 * `@cipherstash/eql`. Non-placeholder steps and every other op field are
 * preserved as-is (only the matched step's `sql` is rewritten), so the swap is
 * non-lossy. Called by the descriptor in `control.ts` so the applied SQL always
 * matches the resolved `@cipherstash/eql` version, not a baked snapshot.
 *
 * Throws if NO placeholder is present: the committed v3 baseline op MUST carry
 * the sentinel, so a missing match means the emit source and this injector have
 * diverged (e.g. real SQL was baked back in, or the sentinel string changed) —
 * fail loudly at descriptor build rather than silently apply the inert comment
 * as the "install" and leave the database with no EQL.
 */
export function withRuntimeEqlSql<T extends OpLike>(ops: readonly T[]): T[] {
  const hasPlaceholder = ops.some((op) =>
    op.execute?.some((step) => step.sql === RUNTIME_EQL_SQL_SENTINEL),
  )
  if (!hasPlaceholder) {
    throw new Error(
      'withRuntimeEqlSql: no op carried RUNTIME_EQL_SQL_SENTINEL — the v3 baseline ops.json must carry the placeholder for runtime EQL-SQL injection. The emit source and this injector have diverged.',
    )
  }
  const sql = readV3InstallSql()
  return ops.map((op) =>
    op.execute?.some((step) => step.sql === RUNTIME_EQL_SQL_SENTINEL)
      ? {
          ...op,
          execute: op.execute.map((step) =>
            step.sql === RUNTIME_EQL_SQL_SENTINEL ? { ...step, sql } : step,
          ),
        }
      : op,
  )
}
