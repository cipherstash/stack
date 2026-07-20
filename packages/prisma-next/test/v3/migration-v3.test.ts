/**
 * v3 baseline migration assertions — the on-disk emitted artefacts for
 * `20260601T0100_install_eql_v3_bundle`.
 *
 * The install SQL is NOT baked into `ops.json`: the committed op carries a
 * placeholder, and the descriptor (`control.ts`) injects `readInstallSql()`
 * from the installed `@cipherstash/eql` at build time. The package installs EQL
 * v3 only: the baseline is an invariant-only genesis edge (`from: null`), and
 * a second invariant-only edge upgrades already-baselined databases to 3.0.2.
 */
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
import {
  materialiseMigrationPackage,
  readMigrationPackage,
} from '@prisma-next/migration-tools/io'
import { describe, expect, it } from 'vitest'
import v3Metadata from '../../migrations/20260601T0100_install_eql_v3_bundle/migration.json' with {
  type: 'json',
}
import v3Ops from '../../migrations/20260601T0100_install_eql_v3_bundle/ops.json' with {
  type: 'json',
}
import v3UpgradeMetadata from '../../migrations/20260720T0000_upgrade_eql_v3_3_0_2/migration.json' with {
  type: 'json',
}
import v3UpgradeOps from '../../migrations/20260720T0000_upgrade_eql_v3_3_0_2/ops.json' with {
  type: 'json',
}
import headRef from '../../migrations/refs/head.json' with { type: 'json' }
import cipherstashDescriptor from '../../src/exports/control'
import {
  CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_INVARIANTS,
} from '../../src/extension-metadata/constants-v3'
import {
  RUNTIME_EQL_SQL_SENTINEL,
  withRuntimeEqlSql,
} from '../../src/migration/eql-bundle-v3'

function runtimeV3Baseline() {
  const migration = cipherstashDescriptor.contractSpace?.migrations.find(
    ({ dirName }) => dirName === CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  )
  if (!migration) {
    throw new Error('runtime descriptor is missing the EQL v3 baseline')
  }
  return migration
}

describe('v3 baseline migration (20260601T0100_install_eql_v3_bundle)', () => {
  it('installs under the v3 invariant with a single data-class rawSql op', () => {
    expect(v3Ops).toHaveLength(1)
    const op = (v3Ops as Array<Record<string, unknown>>)[0]!
    expect(op.id).toBe('cipherstash.install-eql-v3-bundle')
    expect(op.invariantId).toBe(CIPHERSTASH_V3_INVARIANTS.installBundle)
    expect(op.invariantId).toBe('cipherstash:install-eql-v3-bundle-v1')
    // `data`, not `additive`: this genesis edge moves no contract
    // storage, and the aggregate integrity checker rejects a
    // no-storage-movement edge without a data-class op — see the
    // rationale comment in the migration file.
    expect(op.operationClass).toBe('data')
  })

  it('does NOT bake the install SQL into ops.json — it carries the runtime placeholder', () => {
    const op = (
      v3Ops as ReadonlyArray<{
        readonly execute?: ReadonlyArray<{ readonly sql: string }>
      }>
    )[0]!
    // The ~1.7 MB bundle must not be committed here — bumping @cipherstash/eql
    // should not require re-emitting this file. The op carries the sentinel.
    expect(op.execute?.[0]?.sql).toBe(RUNTIME_EQL_SQL_SENTINEL)
    expect(op.execute?.[0]?.sql).not.toContain('CREATE')
    expect(JSON.stringify(v3Ops).length).toBeLessThan(5_000)
    // @cipherstash/eql is pinned exact (matching @cipherstash/stack, which
    // encodes the v3 domain types against this same release).
    expect(releaseManifest.eqlVersion).toBe('3.0.2')
  })

  it('injects readInstallSql() from @cipherstash/eql into the descriptor at build time', () => {
    // control.ts swaps the placeholder for the install SQL of the pinned
    // @cipherstash/eql, so the applied SQL always matches the resolved version.
    const v3Baseline = runtimeV3Baseline()
    const op = (
      v3Baseline.ops as ReadonlyArray<{
        readonly id: string
        readonly execute?: ReadonlyArray<{ readonly sql: string }>
      }>
    ).find((o) => o.id === 'cipherstash.install-eql-v3-bundle')
    if (!op) throw new Error('runtime descriptor is missing the EQL v3 op')
    expect(op.execute?.[0]?.sql).toBe(readInstallSql())
    expect(op.execute?.[0]?.sql).toContain('EQL v3 schema creation')
  })

  it('materialises the runtime descriptor package and verifies it on read', async () => {
    // Round-trip property: the exact package Prisma Next receives from the
    // descriptor must survive its canonical disk writer + integrity-checking
    // reader. This pins the migration hash to the injected SQL, not the
    // sentinel committed in the maintainer artefact.
    const v3Baseline = runtimeV3Baseline()
    expect(v3Baseline.metadata.migrationHash).not.toBe(v3Metadata.migrationHash)

    const root = await mkdtemp(join(tmpdir(), 'prisma-next-eql-v3-'))
    try {
      await materialiseMigrationPackage(root, v3Baseline)
      const reloaded = await readMigrationPackage(
        join(root, v3Baseline.dirName),
      )
      expect(reloaded.metadata).toEqual(v3Baseline.metadata)
      expect(reloaded.ops).toEqual(v3Baseline.ops)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('withRuntimeEqlSql throws if no op carries the sentinel (drift guard)', () => {
    // Matching on the sentinel string (not an op id) makes injection immune to
    // op-id/label drift; a missing sentinel means the emit source and injector
    // diverged, so fail loudly rather than apply the inert comment as install.
    expect(() =>
      withRuntimeEqlSql([{ execute: [{ sql: 'SELECT 1' }] }]),
    ).toThrow(/RUNTIME_EQL_SQL_SENTINEL/)
    // A non-lossy swap: only the sentinel step's `sql` changes; sibling steps
    // and extra fields on the matched op are preserved.
    const [op] = withRuntimeEqlSql([
      {
        id: 'cipherstash.install-eql-v3-bundle',
        execute: [
          { description: 'keep me', sql: RUNTIME_EQL_SQL_SENTINEL },
          { description: 'sibling', sql: 'SELECT 2' },
        ],
      },
    ])
    expect(op.id).toBe('cipherstash.install-eql-v3-bundle')
    expect(op.execute[0].description).toBe('keep me')
    expect(op.execute[0].sql).toBe(readInstallSql())
    expect(op.execute[1]).toEqual({ description: 'sibling', sql: 'SELECT 2' })
  })

  it('emits no add_search_config / remove_search_config ops', () => {
    const json = JSON.stringify(v3Ops)
    expect(json).not.toContain('add_search_config')
    expect(json).not.toContain('remove_search_config')
  })

  it('is an invariant-only genesis edge (from: null → the empty-storage hash)', () => {
    // The package is EQL v3 only, so this is the sole migration and its
    // root: `from: null`. The v3 bundle adds no contract-space storage,
    // so `to` is the empty-storage hash (the contract models no tables).
    expect(v3Metadata.from).toBeNull()
    expect(v3Metadata.to).toBe(headRef.hash)
    expect(v3Metadata.providedInvariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.installBundle,
    ])
  })

  it('adds a distinct 3.0.2 upgrade edge for already-baselined databases', () => {
    expect(CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME).toBe(
      '20260720T0000_upgrade_eql_v3_3_0_2',
    )
    expect(v3UpgradeMetadata.from).toBe(v3Metadata.to)
    expect(v3UpgradeMetadata.to).toBe(v3Metadata.to)
    expect(v3UpgradeMetadata.providedInvariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
    ])
    expect(v3UpgradeOps).toHaveLength(1)
    expect(v3UpgradeOps[0]?.execute[0]?.sql).toBe(RUNTIME_EQL_SQL_SENTINEL)

    const runtimeUpgrade = cipherstashDescriptor.contractSpace?.migrations.find(
      ({ dirName }) => dirName === CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
    )
    expect(runtimeUpgrade).toBeDefined()
    expect(runtimeUpgrade?.metadata.migrationHash).not.toBe(
      v3UpgradeMetadata.migrationHash,
    )
    const runtimeOp = runtimeUpgrade?.ops[0] as
      | { readonly execute?: ReadonlyArray<{ readonly sql: string }> }
      | undefined
    expect(runtimeOp?.execute?.[0]?.sql).toBe(readInstallSql())
  })

  it('pins the head ref at the unchanged hash with all invariants', () => {
    expect(headRef.hash).toBe(v3Metadata.to)
    expect(headRef.invariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.installBundle,
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
    ])
  })
})
