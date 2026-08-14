/**
 * v3 baseline migration assertions — the on-disk emitted artefacts for
 * `20260601T0100_install_eql_v3_bundle` and the 3.0.2 / 3.0.4 upgrade edges.
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
 * Provenance is pinned two ways, kept deliberately separate so the guard
 * survives an EQL version bump. Each published migration has a FROZEN
 * baked-SQL digest tied to its OWN release (never the currently-installed
 * one), so editing published history fails. A single bump-safe LOCKSTEP
 * check then asserts the currently-installed `@cipherstash/eql` release is
 * the SQL baked into *some* published migration — so bumping the dependency
 * without shipping a migration that bakes exactly that release fails, while
 * historical migrations keep their frozen digests untouched.
 */
import { createHash } from 'node:crypto'
import { readdirSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
import {
  materialiseMigrationPackage,
  readMigrationPackage,
} from '@prisma/orm-toolchain/migration-tools/io'
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
import v3Upgrade304Metadata from '../../migrations/20260728T0000_upgrade_eql_v3_3_0_4/migration.json' with {
  type: 'json',
}
import v3Upgrade304Ops from '../../migrations/20260728T0000_upgrade_eql_v3_3_0_4/ops.json' with {
  type: 'json',
}
import headRef from '../../migrations/refs/head.json' with { type: 'json' }
import cipherstashDescriptor from '../../src/exports/control'
import {
  CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME,
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

// The published migration set, with the two content-addressed facts this
// suite freezes for each: the full artefact identity (`migrationHash`) and
// the sha256 of the EQL install SQL baked into its `ops.json`. Both are
// FROZEN literals tied to each migration's own release — a future EQL bump
// ADDS an entry and never edits an existing one. See the 'every published
// migration is frozen' and 'lockstep' tests below for the rules.
const PUBLISHED_MIGRATIONS = [
  {
    dirName: CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
    metadata: v3Metadata,
    ops: v3Ops,
    // Re-pinned once on the 1.0 release branch: the pre-GA re-emit that
    // reclassified the install op `data` → `additive`, added the upgrade
    // invariant-carrier ops (so fresh-database `db init` passes its
    // additive-only policy), and bumped the baked bundle to the pinned
    // eql-3.0.4 release.
    migrationHash:
      '1030654387540db7a053449e478d4b198d8666b360cca9f9c265eddb83b2dd74',
    installSqlSha256:
      '63104a81aac0aebd59fac3765cbe92c3364a7ecbb0bce99e53fbe518d30a0641',
  },
  {
    dirName: CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME,
    metadata: v3Upgrade304Metadata,
    ops: v3Upgrade304Ops,
    migrationHash:
      '94a2ce9c8e973b7a635d92571ff642429e6ebfb7a4600291ee626201e110e13e',
    installSqlSha256:
      '63104a81aac0aebd59fac3765cbe92c3364a7ecbb0bce99e53fbe518d30a0641',
  },
  {
    dirName: CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
    metadata: v3UpgradeMetadata,
    ops: v3UpgradeOps,
    migrationHash:
      '0c56fe6b641c5839c82be72317b2af165fb574b0dcdfc4aa6b50425e371a9d0f',
    installSqlSha256:
      '05860ae47b3760cbba9842b22ddf89cf3f03aa49c33b6386f736c271784094b1',
  },
] as const

const MIGRATIONS_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'migrations',
)

describe('v3 baseline migration (20260601T0100_install_eql_v3_bundle)', () => {
  it('installs under the v3 invariants with three additive rawSql ops', () => {
    // Three ops, all `additive`, so fresh-database `db init` (additive-only
    // policy) can walk this genesis edge: the bundle install itself, plus one
    // no-SQL carrier op per upgrade invariant (3.0.2 and 3.0.4). The baked
    // bundle IS the pinned release, so a fresh install lands at 3.0.4 —
    // which satisfies both invariants, and the shortest-path planner never
    // needs the data-classed upgrade self-edges.
    // `additive` is safe on this edge because the checker's
    // no-op self-edge rule only fires when from === to, and this edge runs
    // from: null → the empty-storage hash — see the rationale comment in
    // the migration file.
    expect(v3Ops).toHaveLength(3)
    const [installOp, carrier302, carrier304] = v3Ops as Array<
      Record<string, unknown>
    >
    expect(installOp!.id).toBe('cipherstash.install-eql-v3-bundle')
    expect(installOp!.invariantId).toBe(CIPHERSTASH_V3_INVARIANTS.installBundle)
    expect(installOp!.invariantId).toBe('cipherstash:install-eql-v3-bundle-v1')
    expect(installOp!.operationClass).toBe('additive')
    expect(carrier302!.id).toBe('cipherstash.install-provides-eql-v3-3-0-2')
    expect(carrier302!.invariantId).toBe(
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
    )
    expect(carrier302!.operationClass).toBe('additive')
    expect(carrier304!.id).toBe('cipherstash.install-provides-eql-v3-3-0-4')
    expect(carrier304!.invariantId).toBe(
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle304,
    )
    expect(carrier304!.operationClass).toBe('additive')
    // The carriers ship no SQL — the preceding install op's bundle is
    // already the pinned release, which satisfies both upgrade invariants.
    expect(carrier302!.execute).toEqual([])
    expect(carrier304!.execute).toEqual([])
  })

  it('every published migration is frozen — artefact identity and baked-SQL provenance are pinned', () => {
    // Each entry pins two content-addressed facts about a PUBLISHED
    // migration: its full artefact identity (`migrationHash`) and the digest
    // of the EQL install SQL baked into its `ops.json`. Both are frozen
    // literals — these artefacts live byte-for-byte in consumers' repos and
    // database ledgers, so a change here is a history rewrite (revert it and
    // ship a NEW migration directory instead). Crucially these are pinned to
    // each migration's OWN release, NOT to the currently-installed
    // @cipherstash/eql, so a future EQL bump leaves them untouched — the
    // lockstep test below is what ties the installed release to a migration.
    for (const m of PUBLISHED_MIGRATIONS) {
      expect(m.metadata.migrationHash, `${m.dirName} migrationHash`).toBe(
        m.migrationHash,
      )
      const sql = firstExecuteSql(m.ops)
      expect(sha256Hex(sql), `${m.dirName} baked SQL digest`).toBe(
        m.installSqlSha256,
      )
      expect(sql).toContain('EQL v3 schema creation')
    }
  })

  it('the migration set on disk is fully pinned — no unpinned or stale entries', () => {
    // Completeness: adding a migration directory without a
    // PUBLISHED_MIGRATIONS entry (or leaving a stale entry after a rename)
    // fails here, so the frozen-history guard above can never silently miss a
    // migration.
    const onDisk = readdirSync(MIGRATIONS_DIR, { withFileTypes: true })
      .filter(
        (e) => e.isDirectory() && e.name !== 'refs' && e.name !== 'snapshots',
      )
      .map((e) => e.name)
      .sort()
    expect(onDisk).toEqual(
      [...PUBLISHED_MIGRATIONS.map((m) => m.dirName)].sort(),
    )
  })

  it('the installed @cipherstash/eql release is baked by some published migration (lockstep)', () => {
    // Bump-safe lockstep: the currently-pinned EQL release must be the SQL
    // baked into at least one published migration. Bumping @cipherstash/eql
    // without adding (or already shipping) a migration that bakes exactly
    // that release's SQL fails here — while historical migrations keep their
    // own frozen digests above, so this never self-destructs on a bump.
    expect(PUBLISHED_MIGRATIONS.map((m) => m.installSqlSha256)).toContain(
      releaseManifest.installSqlSha256,
    )
    // @cipherstash/eql is pinned exact (matching @cipherstash/stack, which
    // encodes the v3 domain types against this same release). Bump this
    // marker together with the dependency and the new migration.
    expect(releaseManifest.eqlVersion).toBe('3.0.4')
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
        { migrationsDir: root },
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
    // Provides ALL invariants (sorted): the install itself plus both
    // upgrade invariants, carried because the baked bundle is the pinned
    // release — this is what lets a fresh database satisfy the head ref
    // from this single all-additive edge.
    expect(v3Metadata.providedInvariants).toEqual(
      [
        CIPHERSTASH_V3_INVARIANTS.installBundle,
        CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
        CIPHERSTASH_V3_INVARIANTS.upgradeBundle304,
      ].sort(),
    )
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
    // The upgrade bakes a re-install-safe bundle (the install SQL
    // drops/recreates the eql_v3 operator schemas and guards the
    // public.eql_v3_* domain creation); its baked-SQL provenance is pinned
    // in PUBLISHED_MIGRATIONS above.
    expect(v3UpgradeOps).toHaveLength(1)

    const runtimeUpgrade = descriptorMigration(
      CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
    )
    expect(runtimeUpgrade.metadata).toEqual(v3UpgradeMetadata)
    expect(runtimeUpgrade.ops).toEqual(v3UpgradeOps)
  })

  it('adds a distinct 3.0.4 upgrade edge for databases on an older bundle', () => {
    expect(CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME).toBe(
      '20260728T0000_upgrade_eql_v3_3_0_4',
    )
    expect(v3Upgrade304Metadata.from).toBe(v3Metadata.to)
    expect(v3Upgrade304Metadata.to).toBe(v3Metadata.to)
    expect(v3Upgrade304Metadata.providedInvariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle304,
    ])
    expect(v3Upgrade304Ops).toHaveLength(1)
    const op = (v3Upgrade304Ops as Array<Record<string, unknown>>)[0]!
    // Self-edge (from === to), so the integrity checker requires a
    // data-class op; only `migrate` (all classes allowed) walks it — fresh
    // databases get 3.0.4 from the all-additive install edge instead.
    expect(op.operationClass).toBe('data')

    const runtimeUpgrade = descriptorMigration(
      CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME,
    )
    expect(runtimeUpgrade.metadata).toEqual(v3Upgrade304Metadata)
    expect(runtimeUpgrade.ops).toEqual(v3Upgrade304Ops)
  })

  it('pins the head ref at the unchanged hash with all invariants', () => {
    expect(headRef.hash).toBe(v3Metadata.to)
    expect(headRef.invariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.installBundle,
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle304,
    ])
  })
})
