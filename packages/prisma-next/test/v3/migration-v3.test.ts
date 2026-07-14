/**
 * v3 baseline migration assertions — the on-disk emitted artefacts for
 * `20260601T0100_install_eql_v3_bundle`.
 *
 * The install SQL is sourced at EMIT time from `@cipherstash/eql/sql`
 * (the same source the stack's `installEqlV3IfNeeded` uses) and baked
 * into `ops.json` byte-for-byte. The edge is invariant-only: the v3
 * bundle creates `public.eql_v3_*` domains + `eql_v3.*` functions but
 * no contract-space storage, so `from === to === <v2 baseline head>`.
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
import { CIPHERSTASH_INVARIANTS } from '../../src/extension-metadata/constants'
import {
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_INVARIANTS,
} from '../../src/extension-metadata/constants-v3'

describe('v3 baseline migration (20260601T0100_install_eql_v3_bundle)', () => {
  it('installs under the v3 invariant with a single additive rawSql op', () => {
    expect(v3Ops).toHaveLength(1)
    const op = (v3Ops as Array<Record<string, unknown>>)[0]!
    expect(op.id).toBe('cipherstash.install-eql-v3-bundle')
    expect(op.invariantId).toBe(CIPHERSTASH_V3_INVARIANTS.installBundle)
    expect(op.invariantId).toBe('cipherstash:install-eql-v3-bundle-v1')
    expect(op.operationClass).toBe('additive')
  })

  it('inlines the @cipherstash/eql install SQL byte-for-byte through ops.json', () => {
    const op = (
      v3Ops as ReadonlyArray<{
        readonly execute?: ReadonlyArray<{ readonly sql: string }>
      }>
    )[0]!
    expect(op.execute?.[0]?.sql).toBe(readInstallSql())
    expect(releaseManifest.eqlVersion).toBe('3.0.0')
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
