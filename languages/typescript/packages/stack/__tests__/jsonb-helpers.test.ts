import { describe, expect, it } from 'vitest'
import {
  buildNestedObject,
  parseJsonbPath,
  toJsonPath,
} from '@/encryption/helpers/jsonb'

describe('toJsonPath', () => {
  it('converts simple path to JSONPath format', () => {
    expect(toJsonPath('name')).toBe('$.name')
  })

  it('converts nested path to JSONPath format', () => {
    expect(toJsonPath('user.email')).toBe('$.user.email')
  })

  it('converts deeply nested path', () => {
    expect(toJsonPath('user.profile.settings.theme')).toBe(
      '$.user.profile.settings.theme',
    )
  })

  it('returns unchanged if already in JSONPath format', () => {
    expect(toJsonPath('$.user.email')).toBe('$.user.email')
  })

  it('normalizes bare $ prefix', () => {
    expect(toJsonPath('$user.email')).toBe('$.user.email')
  })

  it('handles path starting with dot', () => {
    expect(toJsonPath('.user.email')).toBe('$.user.email')
  })

  it('handles root path', () => {
    expect(toJsonPath('$')).toBe('$')
  })

  it('handles empty string', () => {
    expect(toJsonPath('')).toBe('$')
  })

  it('handles array index in path', () => {
    expect(toJsonPath('user.roles[0]')).toBe('$.user.roles[0]')
  })

  it('handles array index with nested property', () => {
    expect(toJsonPath('items[0].name')).toBe('$.items[0].name')
  })

  it('handles already-prefixed path with array index', () => {
    expect(toJsonPath('$.data[2]')).toBe('$.data[2]')
  })

  it('handles nested array indices', () => {
    expect(toJsonPath('matrix[0][1]')).toBe('$.matrix[0][1]')
  })

  it('handles array index at root level', () => {
    expect(toJsonPath('[0].name')).toBe('$[0].name')
  })

  it('preserves already-prefixed root array index', () => {
    expect(toJsonPath('$[0]')).toBe('$[0]')
  })

  it('preserves already-prefixed root array index with property', () => {
    expect(toJsonPath('$[0].name')).toBe('$[0].name')
  })

  it('handles large array index', () => {
    expect(toJsonPath('items[999].value')).toBe('$.items[999].value')
  })

  it('handles deeply nested path after array index', () => {
    expect(toJsonPath('data[0].user.profile.settings')).toBe(
      '$.data[0].user.profile.settings',
    )
  })

  it('handles root array with nested array', () => {
    expect(toJsonPath('[0].items[1].name')).toBe('$[0].items[1].name')
  })
})

describe('buildNestedObject', () => {
  it('builds single-level object', () => {
    expect(buildNestedObject('name', 'alice')).toEqual({ name: 'alice' })
  })

  it('builds two-level nested object', () => {
    expect(buildNestedObject('user.role', 'admin')).toEqual({
      user: { role: 'admin' },
    })
  })

  it('builds deeply nested object', () => {
    expect(buildNestedObject('a.b.c.d', 'value')).toEqual({
      a: { b: { c: { d: 'value' } } },
    })
  })

  it('handles numeric values', () => {
    expect(buildNestedObject('user.age', 30)).toEqual({
      user: { age: 30 },
    })
  })

  it('handles boolean values', () => {
    expect(buildNestedObject('user.active', true)).toEqual({
      user: { active: true },
    })
  })

  it('handles null values', () => {
    expect(buildNestedObject('user.data', null)).toEqual({
      user: { data: null },
    })
  })

  it('handles object values', () => {
    const value = { nested: 'object' }
    expect(buildNestedObject('user.config', value)).toEqual({
      user: { config: { nested: 'object' } },
    })
  })

  it('handles array values', () => {
    expect(buildNestedObject('user.tags', ['admin', 'user'])).toEqual({
      user: { tags: ['admin', 'user'] },
    })
  })

  it('strips JSONPath prefix from path', () => {
    expect(buildNestedObject('$.user.role', 'admin')).toEqual({
      user: { role: 'admin' },
    })
  })

  it('throws on empty path', () => {
    expect(() => buildNestedObject('', 'value')).toThrow('Path cannot be empty')
  })

  it('throws on root-only path', () => {
    expect(() => buildNestedObject('$', 'value')).toThrow(
      'Path must contain at least one segment',
    )
  })

  it('throws on __proto__ segment', () => {
    expect(() => buildNestedObject('__proto__.polluted', 'yes')).toThrow(
      'Path contains forbidden segment: __proto__',
    )
  })

  it('throws on prototype segment', () => {
    expect(() => buildNestedObject('user.prototype.hack', 'yes')).toThrow(
      'Path contains forbidden segment: prototype',
    )
  })

  it('throws on constructor segment', () => {
    expect(() => buildNestedObject('constructor', 'yes')).toThrow(
      'Path contains forbidden segment: constructor',
    )
  })

  it('throws on nested forbidden segment', () => {
    expect(() => buildNestedObject('a.b.__proto__', 'yes')).toThrow(
      'Path contains forbidden segment: __proto__',
    )
  })
})

describe('parseJsonbPath', () => {
  it('parses simple path', () => {
    expect(parseJsonbPath('name')).toEqual(['name'])
  })

  it('parses nested path', () => {
    expect(parseJsonbPath('user.email')).toEqual(['user', 'email'])
  })

  it('parses deeply nested path', () => {
    expect(parseJsonbPath('a.b.c.d')).toEqual(['a', 'b', 'c', 'd'])
  })

  it('strips JSONPath prefix', () => {
    expect(parseJsonbPath('$.user.email')).toEqual(['user', 'email'])
  })

  it('strips bare $ prefix', () => {
    expect(parseJsonbPath('$user.email')).toEqual(['user', 'email'])
  })

  it('handles empty string', () => {
    expect(parseJsonbPath('')).toEqual([])
  })

  it('handles root only', () => {
    expect(parseJsonbPath('$')).toEqual([])
  })

  it('filters empty segments', () => {
    expect(parseJsonbPath('user..email')).toEqual(['user', 'email'])
  })
})
