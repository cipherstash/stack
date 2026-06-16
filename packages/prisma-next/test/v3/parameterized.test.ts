import { type } from 'arktype'
import { describe, expect, it } from 'vitest'
import {
  encryptedStringV3ParamsSchema,
  renderEncryptedStringV3OutputType,
} from '../../src/execution/parameterized'

describe('encryptedStringV3ParamsSchema (bare arktype value, matches v2 idiom)', () => {
  it('accepts a single index choice', () => {
    const out = encryptedStringV3ParamsSchema({ index: 'equality' })
    expect(out).toEqual({ index: 'equality' })
  })
  it('rejects an unknown index', () => {
    expect(encryptedStringV3ParamsSchema({ index: 'nope' }) instanceof type.errors).toBe(true)
  })
})

describe('renderEncryptedStringV3OutputType', () => {
  it('returns the TS output type label (NOT the SQL native type)', () => {
    expect(renderEncryptedStringV3OutputType({ index: 'equality' })).toBe('EncryptedString')
  })
})
