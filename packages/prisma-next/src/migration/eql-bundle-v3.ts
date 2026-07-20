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
 * The v3 migrations do **not** embed the ~1.7 MB install SQL in their
 * `ops.json`. Each committed op carries {@link RUNTIME_EQL_SQL_SENTINEL}, and
 * `src/exports/control.ts` swaps in `readInstallSql()` from the installed
 * `@cipherstash/eql` when it builds the descriptor (see {@link withRuntimeEqlSql}).
 * `@cipherstash/eql` is therefore a runtime dependency, pinned to an exact
 * version
 * to match the version `@cipherstash/stack` encodes its v3 domain TYPES against
 * — the two must move together, so this is a coordinated bump, not a float.
 *
 * The win over baking: upgrading the pinned `@cipherstash/eql` no longer means
 * re-emitting the 1.7 MB `ops.json` (which coupled every EQL bump to a manual
 * re-emit loop) — it is a one-line version bump plus a rebuild.
 *
 * Why this is sound: the v3 bundle migrations are INVARIANT-ONLY self-edges
 * (`from === to`; the bundle declares no contract-space storage — unlike the v2
 * bundle's `eql_v2_configuration`). The install SQL therefore never contributes
 * to the contract-space hash, and `contractSpaceFromJson` passes the ops through
 * with no integrity check on their contents (`verifyMigrationHash` runs only on
 * the disk read path for the user's own repo, never on the in-memory extension
 * descriptor). Swapping the SQL at descriptor-construction time is invisible to
 * the planner. A versioned upgrade invariant ensures databases that have
 * already recorded the original baseline still traverse a new EQL release.
 */
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
import type {
  MigrationOperationClass,
  MigrationPlanOperation,
} from '@prisma-next/framework-components/control'
import { computeMigrationHash } from '@prisma-next/migration-tools/hash'
import type { MigrationMetadata } from '@prisma-next/migration-tools/metadata'

// Re-exported for the live-test helpers, which read the same install SQL to set
// up their databases (`test/live/helpers/eql-v3.ts`, `migration-apply-live-pg`).
export { readInstallSql, releaseManifest }

/**
 * Placeholder each committed v3 bundle op carries in `execute[].sql` in place
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
type HashableOpLike = OpLike & {
  readonly id: string
  readonly label: string
  readonly operationClass: string
  readonly invariantId?: string
}
type RuntimeMigrationMetadata<TMetadata extends MigrationMetadata> = Omit<
  TMetadata,
  'migrationHash'
> & { readonly migrationHash: string }

function isMigrationOperationClass(
  value: string,
): value is MigrationOperationClass {
  return (
    value === 'additive' ||
    value === 'widening' ||
    value === 'destructive' ||
    value === 'data'
  )
}

/**
 * Return `ops` with every placeholder install-SQL step ({@link
 * RUNTIME_EQL_SQL_SENTINEL}) replaced by the install SQL from the installed
 * `@cipherstash/eql`. Non-placeholder steps and every other op field are
 * preserved as-is (only the matched step's `sql` is rewritten), so the swap is
 * non-lossy. Called by the descriptor in `control.ts` so the applied SQL always
 * matches the resolved `@cipherstash/eql` version, not a baked snapshot.
 *
 * Throws if NO placeholder is present: every committed v3 bundle op MUST carry
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
      'withRuntimeEqlSql: no op carried RUNTIME_EQL_SQL_SENTINEL — the v3 bundle ops.json must carry the placeholder for runtime EQL-SQL injection. The emit source and this injector have diverged.',
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

/**
 * Build the complete runtime migration package payload atomically. Replacing
 * the sentinel changes the content-addressed identity of the migration, so the
 * metadata hash MUST be recomputed from the injected operations before the
 * descriptor can materialise the package into a user's migration directory.
 * Keeping both values behind one helper prevents callers from updating the ops
 * while accidentally retaining the sentinel-derived hash.
 */
export function withRuntimeEqlSqlPackage<
  TMetadata extends MigrationMetadata,
  TOp extends HashableOpLike,
>(
  metadata: TMetadata,
  ops: readonly TOp[],
): {
  readonly metadata: RuntimeMigrationMetadata<TMetadata>
  readonly ops: TOp[]
} {
  const runtimeOps = withRuntimeEqlSql(ops)
  const hashOps = runtimeOps.map((op): MigrationPlanOperation => {
    if (!isMigrationOperationClass(op.operationClass)) {
      throw new Error(
        `withRuntimeEqlSqlPackage: invalid migration operation class ${JSON.stringify(op.operationClass)}`,
      )
    }
    // Preserve the target-specific fields consumed by canonical JSON hashing
    // while narrowing the emitted JSON's widened operationClass string.
    return { ...op, operationClass: op.operationClass }
  })
  return {
    metadata: {
      ...metadata,
      migrationHash: computeMigrationHash(metadata, hashOps),
    },
    ops: runtimeOps,
  }
}
