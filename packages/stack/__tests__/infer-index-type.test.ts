import { describe, expect, it } from 'vitest'
import {
  inferIndexType,
  inferQueryOpFromPlaintext,
  validateIndexType,
} from '@/encryption/helpers/infer-index-type'
import { encryptedColumn, encryptedTable } from '@/schema'

describe('infer-index-type helpers', () => {
  const users = encryptedTable('users', {
    email: encryptedColumn('email').equality(),
    bio: encryptedColumn('bio').freeTextSearch(),
    age: encryptedColumn('age').orderAndRange(),
    name: encryptedColumn('name').equality().freeTextSearch(),
  })

  describe('inferIndexType', () => {
    it('returns unique for equality-only column', () => {
      expect(inferIndexType(users.email)).toBe('unique')
    })

    it('returns match for freeTextSearch-only column', () => {
      expect(inferIndexType(users.bio)).toBe('match')
    })

    it('returns ore for orderAndRange-only column', () => {
      expect(inferIndexType(users.age)).toBe('ore')
    })

    it('returns unique when multiple indexes (priority: unique > match > ore)', () => {
      expect(inferIndexType(users.name)).toBe('unique')
    })

    it('returns match when freeTextSearch and orderAndRange (priority: match > ore)', () => {
      const schema = encryptedTable('t', {
        col: encryptedColumn('col').freeTextSearch().orderAndRange(),
      })
      expect(inferIndexType(schema.col)).toBe('match')
    })

    it('throws for column with no indexes', () => {
      const noIndex = encryptedTable('t', { col: encryptedColumn('col') })
      expect(() => inferIndexType(noIndex.col)).toThrow('no indexes configured')
    })

    it('returns ste_vec for searchableJson-only column', () => {
      const schema = encryptedTable('t', {
        col: encryptedColumn('col').searchableJson(),
      })
      expect(inferIndexType(schema.col)).toBe('ste_vec')
    })
  })

  describe('validateIndexType', () => {
    it('does not throw for valid index type', () => {
      expect(() => validateIndexType(users.email, 'unique')).not.toThrow()
    })

    it('throws for unconfigured index type', () => {
      expect(() => validateIndexType(users.email, 'match')).toThrow(
        'not configured',
      )
    })

    it('accepts ste_vec when configured', () => {
      const schema = encryptedTable('t', {
        col: encryptedColumn('col').searchableJson(),
      })
      expect(() => validateIndexType(schema.col, 'ste_vec')).not.toThrow()
    })

    it('rejects ste_vec when not configured', () => {
      const schema = encryptedTable('t', {
        col: encryptedColumn('col').equality(),
      })
      expect(() => validateIndexType(schema.col, 'ste_vec')).toThrow(
        'not configured',
      )
    })
  })

  describe('inferQueryOpFromPlaintext', () => {
    it('returns ste_vec_selector for string plaintext', () => {
      expect(inferQueryOpFromPlaintext('$.user.email')).toBe('ste_vec_selector')
    })

    it('returns default for object plaintext containment', () => {
      expect(inferQueryOpFromPlaintext({ role: 'admin' })).toBe('default')
    })

    it('returns default for array plaintext containment', () => {
      expect(inferQueryOpFromPlaintext(['admin', 'user'])).toBe('default')
    })

    it('returns default for number plaintext', () => {
      expect(inferQueryOpFromPlaintext(42)).toBe('default')
    })

    it('returns default for boolean plaintext', () => {
      expect(inferQueryOpFromPlaintext(true)).toBe('default')
    })
  })
})
