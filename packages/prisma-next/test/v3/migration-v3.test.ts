/**
 * v3 baseline migration assertions — the on-disk emitted artefacts for
 * `20260601T0100_install_eql_v3_bundle`.
 *
 * The install SQL is NOT baked into `ops.json`: the committed op carries a
 * placeholder, and the descriptor (`control.ts`) injects `readInstallSql()`
 * from the installed `@cipherstash/eql` at build time. The edge is
 * invariant-only: the v3 bundle creates `public.eql_v3_*` domains + `eql_v3.*`
 * functions but no contract-space storage, so `from === to === <v2 baseline head>`.
 */
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
import { describe, expect, it } from 'vitest'
import v2Metadata from '../../migrations/20260601T0000_install_eql_bundle/migration.json' with {
  type: 'json',
}
import v3Metadata from '../../migrations/20260601T0100_install_eql_v3_bundle/migration.json' with {
  type: 'json',
}
import v3Ops from '../../migrations/20260601T0100_install_eql_v3_bundle/ops.json' with {
  type: 'json',
}
import headRef from '../../migrations/refs/head.json' with { type: 'json' }
import cipherstashDescriptor from '../../src/exports/control'
import { CIPHERSTASH_INVARIANTS } from '../../src/extension-metadata/constants'
import {
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_INVARIANTS,
} from '../../src/extension-metadata/constants-v3'
import {
  RUNTIME_EQL_SQL_SENTINEL,
  withRuntimeEqlSql,
} from '../../src/migration/eql-bundle-v3'

describe('v3 baseline migration (20260601T0100_install_eql_v3_bundle)', () => {
  it('installs under the v3 invariant with a single data-class rawSql op', () => {
    expect(v3Ops).toHaveLength(1)
    const op = (v3Ops as Array<Record<string, unknown>>)[0]!
    expect(op.id).toBe('cipherstash.install-eql-v3-bundle')
    expect(op.invariantId).toBe(CIPHERSTASH_V3_INVARIANTS.installBundle)
    expect(op.invariantId).toBe('cipherstash:install-eql-v3-bundle-v1')
    // `data`, not `additive`: the edge is a self-edge (from === to),
    // and the aggregate integrity checker rejects self-edges without a
    // data-class op — see the rationale comment in the migration file.
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
    expect(releaseManifest.eqlVersion).toBe('3.0.0')
  })

  it('injects readInstallSql() from @cipherstash/eql into the descriptor at build time', () => {
    // control.ts swaps the placeholder for the install SQL of the pinned
    // @cipherstash/eql, so the applied SQL always matches the resolved version.
    const v3Baseline = cipherstashDescriptor.contractSpace!.migrations[1]!
    const op = (
      v3Baseline.ops as ReadonlyArray<{
        readonly id: string
        readonly execute?: ReadonlyArray<{ readonly sql: string }>
      }>
    ).find((o) => o.id === 'cipherstash.install-eql-v3-bundle')!
    expect(op.execute?.[0]?.sql).toBe(readInstallSql())
    expect(op.execute?.[0]?.sql).toContain('EQL v3 schema creation')
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

  it('sorts after the v2 baseline', () => {
    expect(
      CIPHERSTASH_V3_BASELINE_MIGRATION_NAME >
        '20260601T0000_install_eql_bundle',
    ).toBe(true)
  })

  it('is an invariant-only edge chained from the v2 baseline head', () => {
    // The v3 bundle adds no contract-space storage, so the storage hash
    // does not move: from === to === the v2 baseline's `to`.
    expect(v3Metadata.from).toBe(v2Metadata.to)
    expect(v3Metadata.to).toBe(v2Metadata.to)
    expect(v3Metadata.providedInvariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.installBundle,
    ])
  })

  it('pins the head ref at the (unchanged) hash with BOTH invariants', () => {
    expect(headRef.hash).toBe(v3Metadata.to)
    expect(headRef.invariants).toEqual([
      CIPHERSTASH_INVARIANTS.installBundle,
      CIPHERSTASH_V3_INVARIANTS.installBundle,
    ])
  })
})
