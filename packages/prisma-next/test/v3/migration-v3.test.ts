/**
 * v3 baseline migration assertions — the on-disk emitted artefacts for
 * `20260601T0100_install_eql_v3_bundle` and the 3.0.2 upgrade edge.
 *
 * The install SQL IS baked into `ops.json`: each migration's self-emit
 * script embeds `readVerifiedInstallSql()` — the installed
 * `@cipherstash/eql`'s bundle, digest-verified against the release
 * manifest — so the migration hash covers the exact bytes every
 * consumer's apply executes. The descriptor (`control.ts`) wires the
 * committed artefacts VERBATIM: no runtime transformation, so the
 * migration identity is byte-identical in this repo, in the descriptor,
 * and in every consumer's vendored `migrations/cipherstash/` copy.
 *
 * The provenance pin below (sha256 of the baked SQL === the installed
 * manifest's `installSqlSha256`) is what keeps "the EQL SQL comes from
 * the @cipherstash/eql npm package" true: CI fails if the committed
 * artefact and the pinned dependency ever skew — a version bump without
 * a new migration, or a hand-edit of the artefact.
 */
import { createHash } from 'node:crypto'
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
import { assertInstallSqlDigest } from '../../src/migration/eql-bundle-v3'

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

function firstExecuteSql(ops: unknown): string {
  const op = (
    ops as ReadonlyArray<{
      readonly execute?: ReadonlyArray<{ readonly sql?: unknown }>
    }>
  )[0]
  const sql = op?.execute?.[0]?.sql
  if (typeof sql !== 'string') throw new Error('op carries no execute[0].sql')
  return sql
}

function descriptorMigration(dirName: string) {
  const migration = cipherstashDescriptor.contractSpace?.migrations.find(
    (m) => m.dirName === dirName,
  )
  if (!migration) {
    throw new Error(`runtime descriptor is missing migration ${dirName}`)
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

  it('bakes the install SQL whose digest the pinned @cipherstash/eql release attests (provenance pin)', () => {
    const sql = firstExecuteSql(v3Ops)
    // The baked bytes ARE the installed package's bundle — never
    // hand-maintained. This is the lockstep guard: a @cipherstash/eql
    // bump without a matching migration re-emit (or any edit to the
    // committed artefact) fails here.
    expect(sha256Hex(sql)).toBe(releaseManifest.installSqlSha256)
    expect(sql).toBe(readInstallSql())
    expect(sql).toContain('EQL v3 schema creation')
    // @cipherstash/eql is pinned exact (matching @cipherstash/stack, which
    // encodes the v3 domain types against this same release).
    expect(releaseManifest.eqlVersion).toBe('3.0.2')
  })

  it('the descriptor wires the committed artefacts verbatim — one identity everywhere', () => {
    // No runtime transformation: the descriptor's package must be
    // byte-identical to the committed artefact, which is what the CLI
    // seed phase materialises into a consumer's migrations/cipherstash/
    // and what verifyMigrationHash re-checks on every disk read. (The
    // previous design injected SQL here and recomputed the hash, so the
    // migration's identity varied with the installed @cipherstash/eql —
    // every EQL bump orphaned consumers' vendored copies.)
    const v3Baseline = descriptorMigration(
      CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
    )
    expect(v3Baseline.metadata).toEqual(v3Metadata)
    expect(v3Baseline.ops).toEqual(v3Ops)
  })

  it('materialises the descriptor package and verifies it on read', async () => {
    // Round-trip property: the exact package Prisma Next receives from the
    // descriptor must survive its canonical disk writer + integrity-checking
    // reader (readMigrationPackage recomputes the hash over the read bytes).
    const v3Baseline = descriptorMigration(
      CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
    )
    const root = await mkdtemp(join(tmpdir(), 'prisma-next-eql-v3-'))
    try {
      await materialiseMigrationPackage(root, v3Baseline)
      const reloaded = await readMigrationPackage(
        join(root, v3Baseline.dirName),
      )
      expect(reloaded.metadata).toEqual(v3Metadata)
      expect(reloaded.ops).toEqual(v3Ops)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('assertInstallSqlDigest refuses SQL the release manifest does not attest to', () => {
    // The emit-time tamper/corruption guard: only bytes matching the
    // installed manifest's installSqlSha256 may enter an ops.json.
    const genuine = readInstallSql()
    expect(assertInstallSqlDigest(genuine)).toBe(genuine)
    expect(() => assertInstallSqlDigest(`${genuine}\n-- appended`)).toThrow(
      /digest verification/,
    )
    expect(() => assertInstallSqlDigest('DROP TABLE users;')).toThrow(
      /digest verification/,
    )
  })

  it('emits no add_search_config / remove_search_config ops', () => {
    const json = JSON.stringify(v3Ops)
    expect(json).not.toContain('add_search_config')
    expect(json).not.toContain('remove_search_config')
  })

  it('is an invariant-only genesis edge (from: null → the empty-storage hash)', () => {
    // The package is EQL v3 only, so this is the genesis migration and its
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
    // The upgrade bakes the same digest-attested bundle (the install SQL
    // is re-install-safe: it drops/recreates the eql_v3 operator schemas
    // and guards the public.eql_v3_* domain creation).
    expect(v3UpgradeOps).toHaveLength(1)
    expect(sha256Hex(firstExecuteSql(v3UpgradeOps))).toBe(
      releaseManifest.installSqlSha256,
    )

    const runtimeUpgrade = descriptorMigration(
      CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
    )
    expect(runtimeUpgrade.metadata).toEqual(v3UpgradeMetadata)
    expect(runtimeUpgrade.ops).toEqual(v3UpgradeOps)
  })

  it('pins the head ref at the unchanged hash with all invariants', () => {
    expect(headRef.hash).toBe(v3Metadata.to)
    expect(headRef.invariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.installBundle,
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
    ])
  })

  it('published migration hashes are FROZEN — history is append-only', () => {
    // These literals are the content-addressed identity of migrations that
    // live, byte-for-byte, in consumers' repos and database ledgers. A
    // failure here means published history was rewritten — a re-emit, a
    // label tweak, ANY byte change. There is no legitimate reason for
    // these values to change: revert the edit and ship the change as a
    // NEW migration directory instead. On an EQL version bump, ADD a pin
    // for the new upgrade migration; never modify an existing one.
    expect(v3Metadata.migrationHash).toBe(
      'sha256:2c8739076699b81bcf515f1f8ff23501ff1f2582b933cfd80c5fb5bcc3de9e12',
    )
    expect(v3UpgradeMetadata.migrationHash).toBe(
      'sha256:7bb960435f9cdb7d7c25e4ff70b02fa050a1b8e695541facc47dd87ec3cc634e',
    )
  })
})
