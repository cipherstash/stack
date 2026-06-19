import { describe, expect, it } from 'vitest'
import { EncryptionErrorTypes, getErrorMessage } from '@/errors'

describe('error helpers', () => {
  // -------------------------------------------------------
  // EncryptionErrorTypes
  // -------------------------------------------------------
  describe('EncryptionErrorTypes', () => {
    it('has all expected keys', () => {
      expect(EncryptionErrorTypes).toHaveProperty('ClientInitError')
      expect(EncryptionErrorTypes).toHaveProperty('EncryptionError')
      expect(EncryptionErrorTypes).toHaveProperty('DecryptionError')
      expect(EncryptionErrorTypes).toHaveProperty('LockContextError')
      expect(EncryptionErrorTypes).toHaveProperty('CtsTokenError')
    })

    it('has exactly 5 keys', () => {
      expect(Object.keys(EncryptionErrorTypes)).toHaveLength(5)
    })

    it('error type values match their keys', () => {
      expect(EncryptionErrorTypes.ClientInitError).toBe('ClientInitError')
      expect(EncryptionErrorTypes.EncryptionError).toBe('EncryptionError')
      expect(EncryptionErrorTypes.DecryptionError).toBe('DecryptionError')
      expect(EncryptionErrorTypes.LockContextError).toBe('LockContextError')
      expect(EncryptionErrorTypes.CtsTokenError).toBe('CtsTokenError')
    })

    it('values are all strings', () => {
      for (const value of Object.values(EncryptionErrorTypes)) {
        expect(typeof value).toBe('string')
      }
    })
  })

  // -------------------------------------------------------
  // getErrorMessage
  // -------------------------------------------------------
  describe('getErrorMessage', () => {
    it('extracts message from an Error instance', () => {
      const error = new Error('Something went wrong')
      expect(getErrorMessage(error)).toBe('Something went wrong')
    })

    it('extracts message from a TypeError instance', () => {
      const error = new TypeError('Type mismatch')
      expect(getErrorMessage(error)).toBe('Type mismatch')
    })

    it('returns the string directly when given a string', () => {
      expect(getErrorMessage('plain string error')).toBe('plain string error')
    })

    it('returns empty string when given an empty string', () => {
      expect(getErrorMessage('')).toBe('')
    })

    it('converts a number to string', () => {
      expect(getErrorMessage(42)).toBe('42')
    })

    it('converts zero to string', () => {
      expect(getErrorMessage(0)).toBe('0')
    })

    it('converts NaN to string', () => {
      expect(getErrorMessage(Number.NaN)).toBe('NaN')
    })

    it('converts an object to string', () => {
      const result = getErrorMessage({ code: 'ERR_001' })
      expect(result).toBe('[object Object]')
    })

    it('converts null to string', () => {
      expect(getErrorMessage(null)).toBe('null')
    })

    it('converts undefined to string', () => {
      expect(getErrorMessage(undefined)).toBe('undefined')
    })

    it('converts a boolean to string', () => {
      expect(getErrorMessage(false)).toBe('false')
      expect(getErrorMessage(true)).toBe('true')
    })

    it('converts a symbol to string', () => {
      const sym = Symbol('test')
      expect(getErrorMessage(sym)).toBe('Symbol(test)')
    })

    it('handles Error with empty message', () => {
      const error = new Error('')
      expect(getErrorMessage(error)).toBe('')
    })
  })
})
