import { describe, expect, it } from 'vitest'
import migrationV3 from '../../migrations/20260601T0100_install_eql_v3_bundle/migration'
import { CIPHERSTASH_INVARIANTS } from '../../src/extension-metadata/constants'
import { EQL_V3_BUNDLE_SQL } from '../../src/migration/eql-v3-bundle'

describe('v3 baseline migration', () => {
  it('installs the v3 bundle byte-for-byte under the v3 invariant', () => {
    const ops = new (migrationV3 as unknown as new () => { operations: ReadonlyArray<Record<string, unknown>> })().operations
    const op = ops[0] as {
      invariantId: string
      execute: ReadonlyArray<{ sql: string }>
    }
    expect(op.invariantId).toBe(CIPHERSTASH_INVARIANTS.installBundleV3)
    expect(op.execute[0]!.sql).toBe(EQL_V3_BUNDLE_SQL)
  })

  it('postchecks the eql_v3 schema + text_eq domain', () => {
    const ops = new (migrationV3 as unknown as new () => { operations: ReadonlyArray<Record<string, unknown>> })().operations
    const op = ops[0] as { postcheck: ReadonlyArray<{ sql: string }> }
    const sqls = op.postcheck.map((p) => p.sql).join('\n')
    expect(sqls).toContain('eql_v3')
    expect(sqls).toContain('text_eq')
  })
})
