import { describe, expect, it } from 'vitest'
import * as barrel from '../../src/v3/index.js'

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

  // The key check above sees names, not values: a re-export that resolves to
  // `undefined` still lists its key. Sweep every export the barrel claims.
  it('exports every name as a callable, and types as a namespace', () => {
    const callables = Object.entries(barrel).filter(
      ([name]) => name !== 'types',
    )
    expect(callables).toHaveLength(PUBLIC_SURFACE.length - 1)

    for (const [name, value] of callables) {
      expect(typeof value, name).toBe('function')
    }

    expect(typeof barrel.types.TextSearch).toBe('function')
    expect(barrel.types.IntegerOrd('age')).toBeDefined()
  })
})
