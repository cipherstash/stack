import { describe, expect, it } from 'vitest'
import * as barrel from '@/eql/v3/drizzle'

// Exhaustive, so ADDING an export fails here too. The previous version asserted
// only four names, leaving the codec/column re-exports unpinned and letting a
// new export slip into the public surface unnoticed.
const PUBLIC_SURFACE = [
  'EncryptionOperatorError',
  'EqlV3CodecError',
  'createEncryptionOperatorsV3',
  'extractEncryptionSchemaV3',
  'getEqlV3Column',
  'isEqlV3Column',
  'makeEqlV3Column',
  'types',
  'v3FromDriver',
  'v3ToDriver',
] as const

describe('v3 drizzle barrel', () => {
  it('exports exactly the public surface', () => {
    expect(Object.keys(barrel).sort()).toEqual([...PUBLIC_SURFACE])
  })

  it('exports the public surface', () => {
    expect(typeof barrel.createEncryptionOperatorsV3).toBe('function')
    expect(typeof barrel.extractEncryptionSchemaV3).toBe('function')
    expect(typeof barrel.EncryptionOperatorError).toBe('function')
    expect(typeof barrel.EqlV3CodecError).toBe('function')
    expect(typeof barrel.types.TextSearch).toBe('function')
    expect(barrel.types.IntegerOrd('age')).toBeDefined()
  })

  it('re-exports the codec and column helpers as callables', () => {
    expect(typeof barrel.v3ToDriver).toBe('function')
    expect(typeof barrel.v3FromDriver).toBe('function')
    expect(typeof barrel.getEqlV3Column).toBe('function')
    expect(typeof barrel.isEqlV3Column).toBe('function')
    expect(typeof barrel.makeEqlV3Column).toBe('function')
  })
})
