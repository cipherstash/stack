/**
 * Live-PG apply of the v3 baseline migration bundle.
 *
 * `installEqlV3IfNeeded` applies `readInstallSql()` — and this suite pins that
 * those are byte-for-byte the SQL injected into the shipped control descriptor
 * at runtime, so a green run here IS a green apply of the customer-facing
 * migration op. After install it verifies the observable contract: the
 * `public.eql_v3_*` storage domains and the `eql_v3` operator schema exist, the
 * op carries the `cipherstash:install-eql-v3-bundle-v1` invariant, the op's own
 * postchecks hold against the live database, and no v2-style
 * `add_search_config` was executed (v3 needs no per-column search configuration).
 *
 * It then applies the shipped edges' OWN baked SQL, independent of the
 * installed `@cipherstash/eql`: the genesis edge alone on an empty schema
 * (the `db init` path), a 1.1.x database (eql-3.0.4) walking the 3.0.5,
 * 3.0.6 and 3.1.0 upgrade edges, and a 1.2.x database (eql-3.0.6) walking
 * the 3.1.0 edge (the `migrate` path).
 */

import 'dotenv/config'
import type { MigrationPlanOperation } from '@prisma/orm-framework/components/control'
import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import cipherstashDescriptor from '../../src/exports/control'
import {
  CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_305_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_306_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_310_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_INVARIANTS,
} from '../../src/extension-metadata/constants-v3'
import {
  readInstallSql,
  releaseManifest,
} from '../../src/migration/eql-bundle-v3'
import { installEqlV3IfNeeded, uninstallEqlV3 } from './helpers/eql-v3'
import { liveConnection } from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const INSTALL_OP_ID = 'cipherstash.install-eql-v3-bundle'

type Step = { readonly description: string; readonly sql: string }

/**
 * The SQL target's op shape: `@prisma/orm-target-postgres` adds the
 * `execute` / `postcheck` step lists to the framework's base op.
 */
interface MigrationOp extends MigrationPlanOperation {
  readonly execute: readonly Step[]
  readonly postcheck: readonly Step[]
}

function descriptorOps(dirName: string): readonly MigrationOp[] {
  const migration = cipherstashDescriptor.contractSpace?.migrations.find(
    (m) => m.dirName === dirName,
  )
  if (!migration) throw new Error(`descriptor is missing migration ${dirName}`)
  return migration.ops as readonly MigrationOp[]
}

async function stepHolds(
  sql: postgres.Sql | postgres.TransactionSql,
  step: Step,
): Promise<boolean> {
  const rows = (await sql.unsafe(step.sql)) as unknown as Array<
    Record<string, unknown>
  >
  return Object.values(rows[0] ?? {})[0] === true
}

/** The runner's skip rule: an op whose postchecks all hold is not executed. */
async function postchecksAllHold(
  sql: postgres.TransactionSql,
  op: MigrationOp,
): Promise<boolean> {
  if (op.postcheck.length === 0) return false
  for (const check of op.postcheck) {
    if (!(await stepHolds(sql, check))) return false
  }
  return true
}

async function expectPostchecksHold(
  sql: postgres.Sql | postgres.TransactionSql,
  ops: readonly MigrationOp[],
): Promise<void> {
  for (const op of ops) {
    for (const check of op.postcheck) {
      expect(
        await stepHolds(sql, check),
        `${op.id}: ${check.description}`,
      ).toBe(true)
    }
  }
}

/**
 * The runner's execute → postcheck order, per op. Unlike the runner it
 * never skips a pre-satisfied op; callers that rely on an op really
 * running assert `postchecksAllHold` is false first.
 */
async function applyEdge(
  tx: postgres.TransactionSql,
  dirName: string,
): Promise<void> {
  for (const op of descriptorOps(dirName)) {
    for (const step of op.execute) await tx.unsafe(step.sql)
    await expectPostchecksHold(tx, [op])
  }
}

async function eqlVersion(
  sql: postgres.Sql | postgres.TransactionSql,
): Promise<string | undefined> {
  const [row] = await sql<{ version: string }[]>`
    SELECT eql_v3.version() AS version
  `
  return row?.version
}

/**
 * The baseline's SQL-bearing install op, selected BY ID rather than by
 * position or by "the only op": the edge also carries one no-SQL invariant
 * carrier per EQL upgrade release, and that list grows with every bump.
 * (An earlier version of this helper demanded exactly one op and was left
 * stale by the re-emit that introduced the carriers — it went unnoticed
 * because this suite only runs against a live database.)
 */
function readRuntimeDescriptorOp(): MigrationOp {
  const ops = descriptorOps(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME)
  const op = ops.find(({ id }) => id === INSTALL_OP_ID)
  if (!op) {
    throw new Error(
      `expected an op with id "${INSTALL_OP_ID}" in the v3 baseline migration, got [${ops
        .map(({ id }) => id)
        .join(', ')}]`,
    )
  }
  return op
}

describeLivePg('v3 baseline migration bundle against live Postgres', () => {
  let sql: postgres.Sql

  beforeAll(async () => {
    sql = liveConnection()
    // Reset to a clean pre-install state first: on a reused database
    // `installEqlV3IfNeeded` would short-circuit on the version probe
    // and this suite would never actually exercise the migration SQL.
    // The uninstall removes `eql_v3.version()`, so the install below is
    // guaranteed to apply the full bundle.
    await uninstallEqlV3(sql)
    await installEqlV3IfNeeded(sql)
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  it('the applied SQL is byte-for-byte the runtime descriptor op, carrying the v3 invariant', () => {
    const op = readRuntimeDescriptorOp()
    expect(op.id).toBe(INSTALL_OP_ID)
    expect(op.invariantId).toBe(CIPHERSTASH_V3_INVARIANTS.installBundle)
    // `additive`, not `data`: this is a genesis edge (from: null), not a
    // self-edge, and `db init` runs additive-only. See the migration file.
    expect(op.operationClass).toBe('additive')
    expect(op.execute).toHaveLength(1)
    // Byte identity: what installEqlV3IfNeeded just applied IS the migration
    // bundle the control descriptor gives to `prisma-next migrate`. Red by
    // construction while an EQL bump's migration is on main ahead of the
    // Version Packages PR that moves @cipherstash/eql (DEVELOPING.md).
    expect(op.execute[0]?.sql).toBe(readInstallSql())
  })

  it('installs the pinned release: eql_v3.version() matches the manifest', async () => {
    const [row] = await sql<{ version: string }[]>`
      SELECT eql_v3.version() AS version
    `
    expect(row?.version).toBe(releaseManifest.eqlVersion)
  }, 60_000)

  it('creates the public.eql_v3_* storage domains and the eql_v3 operator schema', async () => {
    const [types] = await sql<
      { text_search: string | null; integer_ord: string | null }[]
    >`
      SELECT
        to_regtype('public.eql_v3_text_search')::text AS text_search,
        to_regtype('public.eql_v3_integer_ord')::text AS integer_ord
    `
    expect(types?.text_search).not.toBeNull()
    expect(types?.integer_ord).not.toBeNull()

    const [schema] = await sql<{ present: boolean }[]>`
      SELECT EXISTS (
        SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v3'
      ) AS present
    `
    expect(schema?.present).toBe(true)
  }, 60_000)

  it("the migration op's own postchecks hold against the live database", async () => {
    const op = readRuntimeDescriptorOp()
    expect(op.postcheck.length).toBeGreaterThan(0)
    for (const check of op.postcheck) {
      const rows = (await sql.unsafe(check.sql)) as unknown as Array<
        Record<string, unknown>
      >
      const value = Object.values(rows[0] ?? {})[0]
      expect(value, check.description).toBe(true)
    }
  }, 60_000)

  // Postchecks compare against literals interpolated at emit time, so one
  // that never matches what its own edge installs fails every customer
  // apply while every offline test stays green.

  it('db init: the genesis edge alone, on an empty eql_v3, satisfies every one of its postchecks', async () => {
    await uninstallEqlV3(sql)
    await sql.begin((tx) =>
      applyEdge(tx, CIPHERSTASH_V3_BASELINE_MIGRATION_NAME),
    )
  }, 240_000)

  /**
   * Put the database on an older bundle through the edge that bakes it,
   * then walk `upgradeDirs` in one transaction, as the runner applies a
   * whole plan, and assert it ends on `endVersion`.
   */
  async function walkFrom(
    startDir: string,
    startVersion: string,
    upgradeDirs: readonly string[],
    endVersion: string,
  ): Promise<void> {
    await uninstallEqlV3(sql)
    await sql.begin((tx) => applyEdge(tx, startDir))
    expect(await eqlVersion(sql)).toBe(startVersion)

    await sql.begin(async (tx) => {
      for (const dirName of upgradeDirs) {
        for (const op of descriptorOps(dirName)) {
          expect(
            await postchecksAllHold(tx, op),
            `${op.id} would be skipped as pre-satisfied`,
          ).toBe(false)
        }
        await applyEdge(tx, dirName)
      }
    })

    expect(await eqlVersion(sql)).toBe(endVersion)
    await expectPostchecksHold(
      sql,
      descriptorOps(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME),
    )
  }

  it('migrate: a 1.1.x database (eql-3.0.4) walks the 3.0.5, 3.0.6 then 3.1.0 edges, installing the bundle three times', async () => {
    // 1.1.x baselines baked the same eql-3.0.4 bytes as the 3.0.4 edge
    // (both pin `63104a81…`). The path is pinned offline in
    // stale-vendored-space.test.ts; this runs its SQL.
    await walkFrom(
      CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME,
      '3.0.4',
      [
        CIPHERSTASH_V3_305_UPGRADE_MIGRATION_NAME,
        CIPHERSTASH_V3_306_UPGRADE_MIGRATION_NAME,
        CIPHERSTASH_V3_310_UPGRADE_MIGRATION_NAME,
      ],
      '3.1.0',
    )
  }, 600_000)

  it('migrate: a 1.2.x database (eql-3.0.6) walks only the 3.1.0 edge', async () => {
    // 1.2.x baselines baked the same eql-3.0.6 bytes as the 3.0.6 edge
    // (both pin `9b6dab78…`).
    await walkFrom(
      CIPHERSTASH_V3_306_UPGRADE_MIGRATION_NAME,
      '3.0.6',
      [CIPHERSTASH_V3_310_UPGRADE_MIGRATION_NAME],
      '3.1.0',
    )
  }, 480_000)

  it('executes no v2-style search configuration (no add_search_config)', () => {
    const bundle = readInstallSql()
    expect(bundle).not.toContain('add_search_config')
    expect(bundle).not.toContain('remove_search_config')
  })
})
