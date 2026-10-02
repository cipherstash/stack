import { describe, expect, it } from 'vitest'
import { getErrorCode } from '@/encryption/helpers/error-code'
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

  // -------------------------------------------------------
  // getErrorCode
  // -------------------------------------------------------
  //
  // The `code` half of the pair above, and the one with a sharp edge:
  // `getErrorMessage` can safely stringify anything, but a code is a value a
  // caller BRANCHES on. protect-ffi 0.31.0 removed the `ProtectError` class
  // this matched with `instanceof`, so the check moved to the code's value —
  // deliberately not to the presence of a `code` property, because Node sets
  // `code` on its own errors. Every failing operation in `encryption/operations`
  // passes its caught error through here, so a presence check would report
  // `ECONNRESET` from a dropped socket as an encryption error code.
  describe('getErrorCode', () => {
    it('returns undefined for a Node error code', () => {
      expect(getErrorCode({ code: 'ECONNRESET' })).toBeUndefined()
      expect(getErrorCode({ code: 'MODULE_NOT_FOUND' })).toBeUndefined()
    })

    it('returns a code the FFI actually emits', () => {
      // A real member of `PROTECT_ERROR_CODES` in protect-ffi 0.31.0.
      expect(getErrorCode({ code: 'UNKNOWN_COLUMN' })).toBe('UNKNOWN_COLUMN')
    })

    it('reads the code off a real Error, not just a plain object', () => {
      const error = Object.assign(new Error('boom'), {
        code: 'INVALID_JSON_PATH',
      })
      expect(getErrorCode(error)).toBe('INVALID_JSON_PATH')
    })

    it('returns undefined for null, undefined, and a code-less error', () => {
      // The implementation optional-chains for exactly this: a `catch` variable
      // is `unknown`, and `throw null` / `throw undefined` are legal JS.
      expect(getErrorCode(null)).toBeUndefined()
      expect(getErrorCode(undefined)).toBeUndefined()
      expect(getErrorCode(new Error('no code'))).toBeUndefined()
      expect(getErrorCode('a bare string')).toBeUndefined()
    })
  })
})
