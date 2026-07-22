/**
 * Structural verification for the CipherStash extension descriptor.
 *
 * **Contract-space package layout.** The descriptor's
 * contract / migrations / head ref now flow through JSON-import
 * declarations from the package's emitted artefacts:
 *
 *   - `<package>/contract.json`
 *   - `<package>/migrations/<dirName>/{migration,ops}.json`
 *   - `<package>/refs/head.json`
 *
 * These assertions lock down the wiring: the descriptor exposes
 * structurally correct values; the EQL v3 install SQL is baked into the
 * committed `ops.json` (digest-verified against `@cipherstash/eql`'s
 * release manifest at emit time — see `src/migration/eql-bundle-v3.ts`)
 * and wired verbatim; and the head ref tracks the latest migration's
 * `to` hash. The exact bytes and provenance of each migration are pinned
 * in `test/v3/migration-v3.test.ts`.
 *
 * **EQL v3 only.** The package installs EQL v3 exclusively. The contract
 * models no storage (the v3 bundle creates `public.eql_v3_*` domains +
 * `eql_v3.*` functions but no contract-space table), and the sole
 * migration is an invariant-only genesis edge (`from: null`).
 *
 * Hash-level values are sourced from the on-disk artefacts (via the
 * descriptor's contractSpace) rather than hand-pinned in the test, so
 * the assertions stay honest under re-emission. Mirrors the synthetic
 * extension's `test/descriptor.test.ts` reference model.
 *
 * @see docs/architecture docs/adrs/ADR 212 - Contract spaces.md
 */

import { assertDescriptorSelfConsistency } from '@prisma-next/migration-tools/spaces'
import { sqlContractCanonicalizationHooks } from '@prisma-next/sql-contract/canonicalization-hooks'
import { describe, expect, it } from 'vitest'
import cipherstashExtensionDescriptor from '../src/exports/control'
import { CIPHERSTASH_SPACE_ID } from '../src/extension-metadata/constants'
import {
  CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_INVARIANTS,
} from '../src/extension-metadata/constants-v3'

describe('cipherstash extension descriptor (contract-space package layout)', () => {
  it('identifies as a SQL extension targeted at postgres', () => {
    expect(cipherstashExtensionDescriptor).toMatchObject({
      kind: 'extension',
      id: CIPHERSTASH_SPACE_ID,
      familyId: 'sql',
      targetId: 'postgres',
    })
  })

  it('exposes a contractSpace that models no storage (EQL v3 only)', () => {
    const space = cipherstashExtensionDescriptor.contractSpace
    expect(space).toBeDefined()
    // Since 0.10 the storage IR is namespace-enveloped (tables under
    // `storage.namespaces.<ns>.entries.table` since 0.13). The v3 bundle
    // creates `public.eql_v3_*` domains + `eql_v3.*` functions but no
    // contract-space table, so the contract models zero tables.
    const namespaces = space!.contractJson.storage.namespaces as Record<
      string,
      { entries?: { table?: Record<string, unknown> } }
    >
    const tables = Object.values(namespaces).flatMap((ns) =>
      Object.keys(ns.entries?.table ?? {}),
    )
    expect(tables).toEqual([])
  })

  it('publishes the v3 baseline and versioned EQL upgrade edges', () => {
    const space = cipherstashExtensionDescriptor.contractSpace!
    expect(space.migrations).toHaveLength(2)
    const v3Baseline = space.migrations[0]!
    expect(v3Baseline.dirName).toBe(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME)
    // Genesis edge (`from: null`): the bundle declares no contract-space
    // storage, so the resulting storage hash is the empty-storage hash —
    // which is exactly `contractJson.storage.storageHash` / the head ref.
    expect(v3Baseline.metadata.from).toBeNull()
    expect(v3Baseline.metadata.to).toBe(space.contractJson.storage.storageHash)
    const v3Upgrade = space.migrations[1]!
    expect(v3Upgrade.dirName).toBe(CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME)
    expect(v3Upgrade.metadata.from).toBe(v3Baseline.metadata.to)
    expect(v3Upgrade.metadata.to).toBe(v3Baseline.metadata.to)
  })

  it('v3 baseline ops carry the installEqlV3Bundle op only', () => {
    const space = cipherstashExtensionDescriptor.contractSpace!
    const v3Baseline = space.migrations[0]!
    const opIds = v3Baseline.ops.map((op) => op.invariantId).filter(Boolean)
    expect(opIds).toEqual([CIPHERSTASH_V3_INVARIANTS.installBundle])
  })

  it('v3 3.0.2 upgrade ops carry a distinct versioned invariant', () => {
    const upgrade = cipherstashExtensionDescriptor.contractSpace!.migrations[1]!
    const opIds = upgrade.ops.map((op) => op.invariantId).filter(Boolean)
    expect(opIds).toEqual([CIPHERSTASH_V3_INVARIANTS.upgradeBundle302])
  })

  it('namespaces every op invariantId in every migration under cipherstash:*', () => {
    for (const migration of cipherstashExtensionDescriptor.contractSpace!
      .migrations) {
      const ids = migration.ops.map((op) => op.invariantId).filter(Boolean)
      expect(ids.length).toBeGreaterThan(0)
      for (const id of ids) {
        expect(id).toMatch(/^cipherstash:/)
      }
    }
  })

  it('carries the baked EQL v3 install SQL in ops.json (not a placeholder)', () => {
    const v3Baseline =
      cipherstashExtensionDescriptor.contractSpace!.migrations[0]!
    const installOp = v3Baseline.ops.find(
      (op) => op.invariantId === CIPHERSTASH_V3_INVARIANTS.installBundle,
    ) as
      | { readonly execute?: ReadonlyArray<{ readonly sql: string }> }
      | undefined
    expect(installOp).toBeDefined()
    // The install SQL is baked into the committed ops.json at emit time and
    // wired verbatim — the descriptor performs no runtime injection. Its
    // exact bytes and digest provenance are pinned in
    // test/v3/migration-v3.test.ts; here we assert only that the op carries
    // the real bundle rather than a placeholder. (Not compared against a
    // live readInstallSql() read: a published migration's SQL is frozen at
    // its own release and must not track the currently-installed one.)
    const sql = installOp?.execute?.[0]?.sql
    expect(sql).toContain('EQL v3 schema creation')
    expect((sql ?? '').length).toBeGreaterThan(100_000)
  })

  it("points the head ref at the latest migration's destination hash with every migration's invariants", () => {
    const space = cipherstashExtensionDescriptor.contractSpace!
    const latest = space.migrations[space.migrations.length - 1]!
    expect(space.headRef.hash).toBe(latest.metadata.to)
    expect([...space.headRef.invariants].sort()).toEqual(
      space.migrations.flatMap((m) => m.metadata.providedInvariants).sort(),
    )
  })

  it('self-consistency check passes — headRef.hash matches re-derived storage hash', () => {
    const space = cipherstashExtensionDescriptor.contractSpace!
    expect(() =>
      assertDescriptorSelfConsistency({
        extensionId: CIPHERSTASH_SPACE_ID,
        target: space.contractJson.target,
        targetFamily: space.contractJson.targetFamily,
        storage: space.contractJson.storage as unknown as Record<
          string,
          unknown
        >,
        headRefHash: space.headRef.hash,
        // The emit pipeline hashes through the SQL family's
        // canonicalization hooks; the recompute must use the same ones.
        shouldPreserveEmpty:
          sqlContractCanonicalizationHooks.shouldPreserveEmpty,
        sortStorage: sqlContractCanonicalizationHooks.sortStorage,
      }),
    ).not.toThrow()
  })
})
