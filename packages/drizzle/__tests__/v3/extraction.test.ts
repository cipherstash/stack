import { pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import {
  extractProtectSchema,
  getEncryptedColumnConfig,
} from '../../src/pg/index'
import { eqlV3Type } from '../../src/pg/v3/eql-v3-type'

describe('extractProtectSchema with v3 columns', () => {
  it('does not throw "No encrypted columns found" for a v3-only table', () => {
    const table = pgTable('v3_only', {
      t_eq: eqlV3Type<string>('t_eq', { dataType: 'text', index: 'equality' }),
      t_ord: eqlV3Type<string>('t_ord', {
        dataType: 'text',
        index: 'orderAndRange',
      }),
    })
    expect(() => extractProtectSchema(table)).not.toThrow()
  })

  it('builds a ProtectTable whose t_eq column carries the equality index + string cast', () => {
    const table = pgTable('v3_only2', {
      t_eq: eqlV3Type<string>('t_eq', { dataType: 'text', index: 'equality' }),
    })
    const schema = extractProtectSchema(table)
    const built = schema.build()
    // Structural check, not a substring of the serialized blob: the built table
    // actually contains the t_eq column, cast as 'string', with the equality
    // (unique) index enabled — equality() sets indexes.unique (schema/src/index.ts:198).
    expect(built.columns).toHaveProperty('t_eq')
    expect(built.columns.t_eq.cast_as).toBe('string')
    expect(built.columns.t_eq.indexes.unique).toBeDefined()
  })

  // The column config map is the only source once pgTable strips _protectConfig.
  // It's anchored on a global-registry Symbol so the ./pg and ./pg/v3 CJS bundles
  // (built without code splitting) share ONE map instead of registering into
  // separate private copies — otherwise mixed-import CJS consumers would see no
  // encrypted columns.
  it('registers v3 column config on the shared global map (cross-bundle safe)', () => {
    const mapKey = Symbol.for('@cipherstash/drizzle/pg:columnConfigMap')
    const sharedMap = (globalThis as Record<symbol, unknown>)[mapKey] as Map<
      string,
      { name: string }
    >
    // Use a column name unique to this test so the global, name-keyed registry
    // can't yield a false positive from another test's prior registration.
    sharedMap.delete('v3_shared_t_eq')
    const table = pgTable('v3_shared', {
      v3_shared_t_eq: eqlV3Type<string>('v3_shared_t_eq', {
        dataType: 'text',
        index: 'equality',
      }),
    })
    expect(sharedMap).toBeInstanceOf(Map)
    expect(sharedMap.get('v3_shared_t_eq')?.name).toBe('v3_shared_t_eq')

    // Simulate pgTable having stripped _protectConfig: resolution must still
    // succeed via the shared map, not the per-column property.
    const column = table.v3_shared_t_eq as unknown as {
      _protectConfig?: unknown
    }
    column._protectConfig = undefined
    expect(
      getEncryptedColumnConfig('v3_shared_t_eq', table.v3_shared_t_eq)?.name,
    ).toBe('v3_shared_t_eq')
  })
})
