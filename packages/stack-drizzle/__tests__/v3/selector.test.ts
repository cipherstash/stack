import { integer, pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import {
  createEncryptionOperatorsV3,
  EncryptionOperatorError,
  parseSelectorSegments,
  reconstructSelectorDocument,
} from '../../src/v3/operators.js'
import { types } from '../../src/v3/types.js'

describe('parseSelectorSegments', () => {
  it('parses $-rooted, bare, and whitespace-padded dot paths', () => {
    expect(parseSelectorSegments('$.a')).toEqual(['a'])
    expect(parseSelectorSegments('$.a.b')).toEqual(['a', 'b'])
    expect(parseSelectorSegments('a.b')).toEqual(['a', 'b'])
    expect(parseSelectorSegments('  $.a.b  ')).toEqual(['a', 'b'])
  })

  it('rejects array-index and wildcard syntax', () => {
    expect(() => parseSelectorSegments('$.items[0]')).toThrow(/array\/wildcard/)
    expect(() => parseSelectorSegments('$.items[*].name')).toThrow(
      /array\/wildcard/,
    )
  })

  it('rejects the empty / root path', () => {
    expect(() => parseSelectorSegments('$')).toThrow(/addresses no field/)
    expect(() => parseSelectorSegments('$.')).toThrow(/addresses no field/)
    expect(() => parseSelectorSegments('')).toThrow(/addresses no field/)
  })

  it('rejects malformed paths (.. / stray dots) rather than silently collapsing', () => {
    expect(() => parseSelectorSegments('$..age')).toThrow(/malformed/)
    expect(() => parseSelectorSegments('$.a..b')).toThrow(/malformed/)
    expect(() => parseSelectorSegments('$.a.')).toThrow(/malformed/)
  })

  it('rejects prototype-pollution keys', () => {
    for (const key of ['__proto__', 'prototype', 'constructor']) {
      expect(() => parseSelectorSegments(`$.${key}`)).toThrow(/forbidden key/)
      expect(() => parseSelectorSegments(`$.a.${key}`)).toThrow(/forbidden key/)
    }
  })
})

describe('reconstructSelectorDocument', () => {
  it('nests the value under the segments', () => {
    expect(reconstructSelectorDocument(['a'], 30)).toEqual({ a: 30 })
    expect(reconstructSelectorDocument(['a', 'b'], 'x')).toEqual({
      a: { b: 'x' },
    })
  })

  it('serializes correctly and creates own keys (no prototype pollution)', () => {
    // parseSelectorSegments rejects __proto__ upstream, but the builder must be
    // safe regardless: a __proto__ segment is an OWN key, not the prototype.
    const doc = reconstructSelectorDocument(['__proto__', 'age'], 1)
    expect(JSON.stringify(doc)).toBe('{"__proto__":{"age":1}}')
    expect(Object.getPrototypeOf(doc)).toBeNull()
    expect({}.age).toBeUndefined() // global prototype untouched
  })
})

describe('ops.selector — up-front guards (no encryption reached)', () => {
  const table = pgTable('selector_guard', {
    id: integer('id').primaryKey(),
    doc: types.Json('doc'),
  })
  // The encrypt methods throw if reached — every case below must reject first.
  const failIfCalled = () => {
    throw new Error('guard should reject before encrypting')
  }
  const ops = createEncryptionOperatorsV3({
    encryptQuery: failIfCalled,
    encrypt: failIfCalled,
  } as never)

  it('rejects a non-scalar leaf value (object / array) — use contains()', async () => {
    await expect(ops.selector(table.doc, '$.a').eq({ x: 1 })).rejects.toThrow(
      /scalar leaf.*contains\(\)/,
    )
    await expect(ops.selector(table.doc, '$.a').eq([1, 2])).rejects.toThrow(
      /scalar leaf/,
    )
  })

  it('rejects ordering a boolean leaf', async () => {
    await expect(ops.selector(table.doc, '$.flag').gt(true)).rejects.toThrow(
      /boolean leaf has no ordering/,
    )
  })

  it('allows equality on a boolean leaf (would reach encryption)', async () => {
    // eq on a boolean is permitted by the guard; it fails only because the mock
    // encrypt throws — proving the guard passed it through.
    await expect(ops.selector(table.doc, '$.flag').eq(true)).rejects.toThrow(
      /guard should reject before encrypting/,
    )
  })

  it('surfaces path errors as EncryptionOperatorError with context', async () => {
    await expect(
      ops.selector(table.doc, '$.items[0]').eq(1),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
    await expect(ops.selector(table.doc, '$').eq(1)).rejects.toThrow(
      /addresses no field/,
    )
    await expect(ops.selector(table.doc, '$.__proto__').eq(1)).rejects.toThrow(
      /forbidden key/,
    )
  })
})
