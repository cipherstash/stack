import { describe, expect, it } from 'vitest'
import { encryptedStringV3 } from '../../src/exports/column-types'
import { CIPHERSTASH_STRING_V3_CODEC_ID } from '../../src/extension-metadata/constants'

describe('encryptedStringV3', () => {
  it('lowers to the v3 codec id with the chosen index in typeParams', () => {
    const d = encryptedStringV3({ index: 'equality' })
    expect(d.codecId).toBe(CIPHERSTASH_STRING_V3_CODEC_ID)
    expect(d.typeParams).toEqual({ index: 'equality' })
  })
  it('carries the base storage domain as nativeType (per-column domain emitted by the migration hook)', () => {
    expect(encryptedStringV3({ index: 'orderAndRange' }).nativeType).toBe('eql_v3.text')
  })
  it('rejects an unknown index', () => {
    // @ts-expect-error invalid index
    expect(() => encryptedStringV3({ index: 'nope' })).toThrow()
  })
})
