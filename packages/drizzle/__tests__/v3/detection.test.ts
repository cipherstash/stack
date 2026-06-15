import { describe, expect, it } from 'vitest'
import { isEncryptedSqlName } from '../../src/pg/index'

describe('isEncryptedSqlName', () => {
  it('recognises the v2 composite type', () => {
    expect(isEncryptedSqlName('eql_v2_encrypted')).toBe(true)
  })

  it('recognises every v3 capability + storage domain', () => {
    expect(isEncryptedSqlName('eql_v3.text')).toBe(true)
    expect(isEncryptedSqlName('eql_v3.text_eq')).toBe(true)
    expect(isEncryptedSqlName('eql_v3.text_match')).toBe(true)
    expect(isEncryptedSqlName('eql_v3.text_ord')).toBe(true)
  })

  it('rejects unrelated sql names', () => {
    expect(isEncryptedSqlName('text')).toBe(false)
    expect(isEncryptedSqlName('jsonb')).toBe(false)
    expect(isEncryptedSqlName(undefined)).toBe(false)
  })
})
