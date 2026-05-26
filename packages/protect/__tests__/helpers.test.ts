import { describe, expect, it } from 'vitest'
import {
  bulkModelsToEncryptedPgComposites,
  encryptedToCompositeLiteral,
  encryptedToPgComposite,
  isEncryptedPayload,
  isEncryptedScalarQuery,
  modelToEncryptedPgComposites,
} from '../src/helpers'

describe('helpers', () => {
  describe('encryptedToPgComposite', () => {
    it('should convert encrypted payload to pg composite', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: {
          c: 'iv',
          t: 't',
        },
        k: 'k',
        ob: ['a', 'b'],
        bf: [1, 2, 3],
        hm: 'hm',
      }

      const pgComposite = encryptedToPgComposite(encrypted)
      expect(pgComposite).toEqual({
        data: encrypted,
      })
    })
  })

  describe('encryptedToCompositeLiteral', () => {
    it('should convert encrypted payload to pg composite literal string', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: {
          c: 'iv',
          t: 't',
        },
      }

      const literal = encryptedToCompositeLiteral(encrypted)
      // Should produce PostgreSQL composite literal format: ("json_string")
      expect(literal).toMatch(/^\(.*\)$/)
      // The inner content should be a valid JSON string (double-stringified)
      const innerContent = literal.slice(1, -1) // Remove outer parentheses
      expect(() => JSON.parse(innerContent)).not.toThrow()
      // Parsing the inner content should give us the original JSON
      const parsedJson = JSON.parse(JSON.parse(innerContent))
      expect(parsedJson).toEqual(encrypted)
    })
  })

  describe('isEncryptedPayload', () => {
    it('should return true for valid encrypted payload', () => {
      const encrypted = {
        v: 1,
        c: 'ciphertext',
        i: { c: 'iv', t: 't' },
      }
      expect(isEncryptedPayload(encrypted)).toBe(true)
    })

    it('should return false for null', () => {
      expect(isEncryptedPayload(null)).toBe(false)
    })

    it('should return false for non-encrypted object', () => {
      expect(isEncryptedPayload({ foo: 'bar' })).toBe(false)
    })
  })

  describe('isEncryptedScalarQuery', () => {
    const baseIndex = { c: 'email', t: 'users' }

    it('returns true for a unique (hm) scalar query term', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          i: baseIndex,
          hm: 'abc123',
        }),
      ).toBe(true)
    })

    it('returns true for a match (bf) scalar query term', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          i: baseIndex,
          bf: [1, 2, 3],
        }),
      ).toBe(true)
    })

    it('returns true for an ore (ob) scalar query term', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          i: baseIndex,
          ob: ['a', 'b'],
        }),
      ).toBe(true)
    })

    it('returns false when the storage ciphertext (c) is present', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          i: baseIndex,
          c: 'ciphertext',
          hm: 'abc123',
        }),
      ).toBe(false)
    })

    it('returns false when more than one lookup term is present', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          i: baseIndex,
          hm: 'abc123',
          bf: [1, 2, 3],
        }),
      ).toBe(false)
    })

    it('returns false when no lookup term is present', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          i: baseIndex,
        }),
      ).toBe(false)
    })

    it('returns false for a ste_vec query term (k: "sv")', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'sv',
          i: baseIndex,
          sv: [{ s: 'selector', t: 'term' }],
        }),
      ).toBe(false)
    })

    it('returns false when version (v) is missing or not a number', () => {
      expect(
        isEncryptedScalarQuery({
          k: 'ct',
          i: baseIndex,
          hm: 'abc123',
        }),
      ).toBe(false)
      expect(
        isEncryptedScalarQuery({
          v: '2',
          k: 'ct',
          i: baseIndex,
          hm: 'abc123',
        }),
      ).toBe(false)
    })

    it('returns false when index (i) is missing or null', () => {
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          hm: 'abc123',
        }),
      ).toBe(false)
      expect(
        isEncryptedScalarQuery({
          v: 2,
          k: 'ct',
          i: null,
          hm: 'abc123',
        }),
      ).toBe(false)
    })

    it('returns false for null, primitives, and non-objects', () => {
      expect(isEncryptedScalarQuery(null)).toBe(false)
      expect(isEncryptedScalarQuery(undefined)).toBe(false)
      expect(isEncryptedScalarQuery('string')).toBe(false)
      expect(isEncryptedScalarQuery(42)).toBe(false)
    })
  })

  describe('modelToEncryptedPgComposites', () => {
    it('should transform model with encrypted fields', () => {
      const model = {
        name: 'John',
        email: {
          v: 1,
          c: 'encrypted_email',
          i: { c: 'iv', t: 't' },
        },
        age: 30,
      }

      const result = modelToEncryptedPgComposites(model)
      expect(result).toEqual({
        name: 'John',
        email: {
          data: {
            v: 1,
            c: 'encrypted_email',
            i: { c: 'iv', t: 't' },
          },
        },
        age: 30,
      })
    })
  })

  describe('bulkModelsToEncryptedPgComposites', () => {
    it('should transform multiple models with encrypted fields', () => {
      const models = [
        {
          name: 'John',
          email: {
            v: 1,
            c: 'encrypted_email1',
            i: { c: 'iv', t: 't' },
          },
        },
        {
          name: 'Jane',
          email: {
            v: 1,
            c: 'encrypted_email2',
            i: { c: 'iv', t: 't' },
          },
        },
      ]

      const result = bulkModelsToEncryptedPgComposites(models)
      expect(result).toEqual([
        {
          name: 'John',
          email: {
            data: {
              v: 1,
              c: 'encrypted_email1',
              i: { c: 'iv', t: 't' },
            },
          },
        },
        {
          name: 'Jane',
          email: {
            data: {
              v: 1,
              c: 'encrypted_email2',
              i: { c: 'iv', t: 't' },
            },
          },
        },
      ])
    })
  })
})
