import { describe, expect, it } from 'vitest'
import { cipherstashStringV3CodecHooks } from '../../src/migration/codec-hooks-v3'

describe('cipherstashStringV3CodecHooks.expandNativeType', () => {
  const expand = cipherstashStringV3CodecHooks.expandNativeType!

  it('returns the per-index domain for the column', () => {
    expect(expand({ nativeType: 'eql_v3.text', typeParams: { index: 'equality' } })).toBe('eql_v3.text_eq')
    expect(expand({ nativeType: 'eql_v3.text', typeParams: { index: 'freeTextSearch' } })).toBe('eql_v3.text_match')
    expect(expand({ nativeType: 'eql_v3.text', typeParams: { index: 'orderAndRange' } })).toBe('eql_v3.text_ord')
  })

  it('falls back to the base storage domain when no index is present', () => {
    expect(expand({ nativeType: 'eql_v3.text' })).toBe('eql_v3.text')
  })
})

describe('cipherstashStringV3CodecHooks.onFieldEvent', () => {
  it('emits NO ops on field add (the domain encodes the capability — no add_search_config)', () => {
    const ops = cipherstashStringV3CodecHooks.onFieldEvent!('added', {
      tableName: 'user_v3',
      fieldName: 'email',
      newField: { typeParams: { index: 'equality' } },
    } as never)
    expect(ops).toEqual([])
  })
})
