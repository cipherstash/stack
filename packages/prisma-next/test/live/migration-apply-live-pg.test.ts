/**
 * Live-PG apply of the v3 baseline migration bundle.
 *
 * `installEqlV3IfNeeded` applies `readInstallSql()` — and this suite
 * pins that those are byte-for-byte the SQL baked into the shipped
 * migration's `ops.json` (`migrations/20260601T0100_install_eql_v3_bundle`),
 * so a green run here IS a green apply of the customer-facing
 * migration op. After install it verifies the observable contract: the
 * `public.eql_v3_*` storage domains and the `eql_v3` operator schema
 * exist, the op carries the `cipherstash:install-eql-v3-bundle-v1`
 * invariant, the op's own postchecks hold against the live database,
 * and no v2-style `add_search_config` was executed (v3 needs no
 * per-column search configuration).
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'pathe'
import type postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { CIPHERSTASH_V3_INVARIANTS } from '../../src/extension-metadata/constants-v3'
import {
  readInstallSql,
  releaseManifest,
} from '../../src/migration/eql-bundle-v3'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import { liveConnection } from './helpers/harness'
import { describeLivePg } from './helpers/live-gate'

const MIGRATION_DIR = join(
  dirname(dirname(dirname(fileURLToPath(import.meta.url)))),
  'migrations',
  '20260601T0100_install_eql_v3_bundle',
)

interface MigrationOp {
  readonly id: string
  readonly invariantId: string
  readonly operationClass: string
  readonly execute: ReadonlyArray<{
    readonly description: string
    readonly sql: string
  }>
  readonly postcheck: ReadonlyArray<{
    readonly description: string
    readonly sql: string
  }>
}

function readOpsFixture(): MigrationOp {
  const ops = JSON.parse(
    readFileSync(join(MIGRATION_DIR, 'ops.json'), 'utf8'),
  ) as MigrationOp[]
  const op = ops[0]
  if (ops.length !== 1 || !op) {
    throw new Error(
      `expected exactly one op in the v3 baseline migration, got ${ops.length}`,
    )
  }
  return op
}

describeLivePg('v3 baseline migration bundle against live Postgres', () => {
  let sql: postgres.Sql

  beforeAll(async () => {
    sql = liveConnection()
    await installEqlV3IfNeeded(sql)
  }, 240_000)

  afterAll(async () => {
    if (sql) await sql.end()
  })

  it('the applied SQL is byte-for-byte the shipped migration op, carrying the v3 invariant', () => {
    const op = readOpsFixture()
    expect(op.id).toBe('cipherstash.install-eql-v3-bundle')
    expect(op.invariantId).toBe(CIPHERSTASH_V3_INVARIANTS.installBundle)
    expect(op.operationClass).toBe('additive')
    expect(op.execute).toHaveLength(1)
    // Byte identity: what installEqlV3IfNeeded just applied IS the
    // migration bundle a customer's `prisma-next migrate` applies.
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
    const op = readOpsFixture()
    expect(op.postcheck.length).toBeGreaterThan(0)
    for (const check of op.postcheck) {
      const rows = (await sql.unsafe(check.sql)) as unknown as Array<
        Record<string, unknown>
      >
      const value = Object.values(rows[0] ?? {})[0]
      expect(value, check.description).toBe(true)
    }
  }, 60_000)

  it('executes no v2-style search configuration (no add_search_config)', () => {
    const bundle = readInstallSql()
    expect(bundle).not.toContain('add_search_config')
    expect(bundle).not.toContain('remove_search_config')
  })
})
