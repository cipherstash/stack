import { describe, expect, it } from 'vitest'
import * as barrel from '@/eql/v3/drizzle'

describe('v3 drizzle barrel', () => {
  it('exports the public surface', () => {
    expect(typeof barrel.createEncryptionOperatorsV3).toBe('function')
    expect(typeof barrel.extractEncryptionSchemaV3).toBe('function')
    expect(typeof barrel.EncryptionOperatorError).toBe('function')
    expect(typeof barrel.types.TextSearch).toBe('function')
    expect(barrel.types.IntegerOrd('age')).toBeDefined()
  })
})
