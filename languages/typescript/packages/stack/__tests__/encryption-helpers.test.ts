import { describe, expect, it } from 'vitest'
import {
  bulkModelsToEncryptedPgComposites,
  encryptedToCompositeLiteral,
  encryptedToEscapedCompositeLiteral,
  encryptedToPgComposite,
  isEncryptedPayload,
  modelToEncryptedPgComposites,
  toFfiKeysetIdentifier,
} from '../src/encryption/helpers/index.js'

describe('encryption helpers', () => {
  // -------------------------------------------------------
  // isEncryptedPayload
  // -------------------------------------------------------
  describe('isEncryptedPayload', () => {
    it('returns true for valid encrypted object with "c" field', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'column', t: 'table' },
      }
      expect(isEncryptedPayload(encrypted)).toBe(true)
    })

    it('returns true for valid encrypted object with "sv" field', () => {
      const encrypted = {
        v: 1,
        sv: [{ some: 'vec' }],
        i: { c: 'column', t: 'table' },
      }
      expect(isEncryptedPayload(encrypted)).toBe(true)
    })

    it('returns true for encrypted object with both "c" and "sv" fields', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        sv: [{ some: 'vec' }],
        i: { c: 'column', t: 'table' },
      }
      expect(isEncryptedPayload(encrypted)).toBe(true)
    })

    it('returns true for encrypted object with additional fields', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'column', t: 'table' },
        k: 'keyset',
        ob: ['a', 'b'],
        bf: [1, 2, 3],
        hm: 'hm',
      }
      expect(isEncryptedPayload(encrypted)).toBe(true)
    })

    it('returns false for null', () => {
      expect(isEncryptedPayload(null)).toBe(false)
    })

    it('returns false for undefined', () => {
      expect(isEncryptedPayload(undefined)).toBe(false)
    })

    it('returns false for a string', () => {
      expect(isEncryptedPayload('hello')).toBe(false)
    })

    it('returns false for a number', () => {
      expect(isEncryptedPayload(42)).toBe(false)
    })

    it('returns false for a boolean', () => {
      expect(isEncryptedPayload(true)).toBe(false)
    })

    it('returns false for an empty object', () => {
      expect(isEncryptedPayload({})).toBe(false)
    })

    it('returns false for object missing "v" field', () => {
      expect(isEncryptedPayload({ c: 'cipher', i: {} })).toBe(false)
    })

    it('returns false for object missing "i" field', () => {
      expect(isEncryptedPayload({ v: 1, c: 'cipher' })).toBe(false)
    })

    it('returns false for object missing both "c" and "sv" fields', () => {
      expect(isEncryptedPayload({ v: 1, i: {} })).toBe(false)
    })

    it('returns false for an array', () => {
      expect(isEncryptedPayload([1, 2, 3])).toBe(false)
    })

    it('returns false for object with only "v" and "c" (missing "i")', () => {
      expect(isEncryptedPayload({ v: 1, c: 'cipher' })).toBe(false)
    })
  })

  // -------------------------------------------------------
  // toFfiKeysetIdentifier
  // -------------------------------------------------------
  describe('toFfiKeysetIdentifier', () => {
    it('converts { name: "my-keyset" } to { Name: "my-keyset" }', () => {
      const result = toFfiKeysetIdentifier({ name: 'my-keyset' })
      expect(result).toEqual({ Name: 'my-keyset' })
    })

    it('converts { id: "uuid-here" } to { Uuid: "uuid-here" }', () => {
      const result = toFfiKeysetIdentifier({ id: 'uuid-here' })
      expect(result).toEqual({ Uuid: 'uuid-here' })
    })

    it('converts { id: "550e8400-e29b-41d4-a716-446655440000" } to correct Uuid', () => {
      const uuid = '550e8400-e29b-41d4-a716-446655440000'
      const result = toFfiKeysetIdentifier({ id: uuid })
      expect(result).toEqual({ Uuid: uuid })
    })

    it('returns undefined when keyset is undefined', () => {
      const result = toFfiKeysetIdentifier(undefined)
      expect(result).toBeUndefined()
    })

    it('converts name with special characters', () => {
      const result = toFfiKeysetIdentifier({ name: 'my-keyset_v2.0' })
      expect(result).toEqual({ Name: 'my-keyset_v2.0' })
    })
  })

  // -------------------------------------------------------
  // encryptedToCompositeLiteral
  // -------------------------------------------------------
  describe('encryptedToCompositeLiteral', () => {
    it('produces correct PostgreSQL composite literal format', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'column', t: 'table' },
      }
      const literal = encryptedToCompositeLiteral(encrypted)

      // Should be wrapped in parentheses
      expect(literal).toMatch(/^\(.*\)$/)

      // The inner content should be a double-stringified JSON
      const inner = literal.slice(1, -1)
      expect(() => JSON.parse(inner)).not.toThrow()

      // Parsing twice should give us back the original object
      const parsed = JSON.parse(JSON.parse(inner))
      expect(parsed).toEqual(encrypted)
    })

    it('handles encrypted object with additional fields', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'column', t: 'table' },
        k: 'keyset',
        ob: ['a'],
        bf: [1],
        hm: 'hash',
      }
      const literal = encryptedToCompositeLiteral(encrypted)
      const inner = literal.slice(1, -1)
      const parsed = JSON.parse(JSON.parse(inner))
      expect(parsed).toEqual(encrypted)
    })
  })

  // -------------------------------------------------------
  // encryptedToEscapedCompositeLiteral
  // -------------------------------------------------------
  describe('encryptedToEscapedCompositeLiteral', () => {
    it('produces an escaped version of composite literal', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'column', t: 'table' },
      }
      const escaped = encryptedToEscapedCompositeLiteral(encrypted)
      // Should be a JSON string wrapping the composite literal
      expect(typeof escaped).toBe('string')
      // Parsing it should give us the composite literal
      const compositeLiteral = JSON.parse(escaped)
      expect(compositeLiteral).toMatch(/^\(.*\)$/)
    })
  })

  // -------------------------------------------------------
  // encryptedToPgComposite
  // -------------------------------------------------------
  describe('encryptedToPgComposite', () => {
    it('produces correct structure with data wrapper', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'column', t: 'table' },
      }
      const result = encryptedToPgComposite(encrypted)
      expect(result).toEqual({ data: encrypted })
    })

    it('wraps the entire encrypted object inside data', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'col', t: 'tbl' },
        k: 'key',
        ob: ['order'],
        bf: [1, 2],
        hm: 'hmac',
      }
      const result = encryptedToPgComposite(encrypted)
      expect(result.data).toBe(encrypted) // same reference
    })
  })

  // -------------------------------------------------------
  // modelToEncryptedPgComposites
  // -------------------------------------------------------
  describe('modelToEncryptedPgComposites', () => {
    it('transforms encrypted fields in a model to pg composites', () => {
      const model = {
        name: 'Alice',
        email: {
          v: 1,
          c: 'encrypted_email',
          i: { c: 'email', t: 'users' },
        },
        age: 30,
      }

      const result = modelToEncryptedPgComposites(model)
      expect(result).toEqual({
        name: 'Alice',
        email: {
          data: {
            v: 1,
            c: 'encrypted_email',
            i: { c: 'email', t: 'users' },
          },
        },
        age: 30,
      })
    })

    it('leaves non-encrypted fields unchanged', () => {
      const model = {
        name: 'Bob',
        status: 'active',
        count: 5,
      }
      const result = modelToEncryptedPgComposites(model)
      expect(result).toEqual(model)
    })
  })

  // -------------------------------------------------------
  // bulkModelsToEncryptedPgComposites
  // -------------------------------------------------------
  describe('bulkModelsToEncryptedPgComposites', () => {
    it('transforms multiple models', () => {
      const models = [
        {
          name: 'Alice',
          email: { v: 1, c: 'enc1', i: { c: 'email', t: 'users' } },
        },
        {
          name: 'Bob',
          email: { v: 1, c: 'enc2', i: { c: 'email', t: 'users' } },
        },
      ]

      const result = bulkModelsToEncryptedPgComposites(models)
      expect(result).toHaveLength(2)
      expect(result[0].email).toEqual({
        data: { v: 1, c: 'enc1', i: { c: 'email', t: 'users' } },
      })
      expect(result[1].email).toEqual({
        data: { v: 1, c: 'enc2', i: { c: 'email', t: 'users' } },
      })
      expect(result[0].name).toBe('Alice')
      expect(result[1].name).toBe('Bob')
    })

    it('handles empty array', () => {
      const result = bulkModelsToEncryptedPgComposites([])
      expect(result).toEqual([])
    })
  })
})
