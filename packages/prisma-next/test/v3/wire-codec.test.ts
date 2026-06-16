import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { decodeEqlV3Wire, encodeEqlV3Wire } from '../../src/v3/wire-codec'

describe('encodeEqlV3Wire', () => {
  it('serialises an object payload as plain jsonb text', () => {
    expect(encodeEqlV3Wire({ v: 2, i: { t: 'users', c: 'email' }, hm: 'abc' })).toBe(
      '{"v":2,"i":{"t":"users","c":"email"},"hm":"abc"}',
    )
  })
  it('maps null/undefined to SQL NULL (never the JSON null literal)', () => {
    // the v3 domains CHECK jsonb_typeof = 'object'; a JSONB null fails the domain.
    expect(encodeEqlV3Wire(null)).toBeNull()
    expect(encodeEqlV3Wire(undefined)).toBeNull()
  })
})

describe('decodeEqlV3Wire', () => {
  it('parses a jsonb string', () => {
    expect(decodeEqlV3Wire('{"hm":"abc"}')).toEqual({ hm: 'abc' })
  })
  it('passes through an already-parsed object (postgres auto-parse)', () => {
    expect(decodeEqlV3Wire({ hm: 'abc' })).toEqual({ hm: 'abc' })
  })
  it('passes through null/undefined', () => {
    expect(decodeEqlV3Wire(null)).toBeNull()
    expect(decodeEqlV3Wire(undefined)).toBeUndefined()
  })
})

describe('wire round-trip (property)', () => {
  it('decode∘encode is identity for arbitrary JSON objects', () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string(), fc.jsonValue()), (obj) => {
        const wire = encodeEqlV3Wire(obj)
        expect(decodeEqlV3Wire(wire as string)).toEqual(obj)
      }),
    )
  })
})
