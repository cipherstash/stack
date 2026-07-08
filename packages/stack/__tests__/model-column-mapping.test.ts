import { describe, expect, it } from 'vitest'
import { resolveEncryptColumnMap } from '@/encryption/helpers/model-helpers'
import { encryptedTable, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'

// `resolveEncryptColumnMap` is how the model path reconciles the two keyings a
// table can use: models are matched by JS property name, but the FFI / encrypt
// config is addressed by DB column name. A mismatch here is a real data-leak
// bug — a schema field that fails to match is passed through as plaintext.
describe('resolveEncryptColumnMap', () => {
  it('v3: matches by JS property, addresses the FFI by DB name', () => {
    const users = encryptedTable('users', {
      createdOn: types.Date('created_on'),
      notes: types.Text('notes'), // property == name
    })

    const { columnPaths, toColumnName } = resolveEncryptColumnMap(users)

    // Fields are matched against JS property names (what a model is keyed by)…
    expect(columnPaths.sort()).toEqual(['createdOn', 'notes'])
    // …and each maps to the DB name the config/FFI is keyed by.
    expect(toColumnName('createdOn')).toBe('created_on')
    expect(toColumnName('notes')).toBe('notes')
  })

  it('v2: no property→DB map, so both keying schemes are the JS property', () => {
    // v2 `build()` keys columns by the JS property, so matching and addressing
    // use that same key — the resolver must fall back to identity and leave the
    // v2 model path unchanged.
    const legacy = encryptedTableV2('legacy', {
      fooBar: encryptedColumn('foo_bar'),
    })

    const { columnPaths, toColumnName } = resolveEncryptColumnMap(legacy)

    expect(columnPaths).toEqual(['fooBar'])
    expect(toColumnName('fooBar')).toBe('fooBar')
  })
})
