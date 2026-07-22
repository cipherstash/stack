import { describe, expect, it } from 'vitest'
import {
  candidateDomains,
  defaultDomain,
  pgTypeToDataType,
} from '../introspect.js'

describe('pgTypeToDataType', () => {
  it('maps integer/float/numeric udt names to number', () => {
    for (const udt of ['int2', 'int4', 'int8', 'float4', 'float8', 'numeric']) {
      expect(pgTypeToDataType(udt)).toBe('number')
    }
  })

  it('maps bool to boolean, date/timestamp to date, json/jsonb to json', () => {
    expect(pgTypeToDataType('bool')).toBe('boolean')
    expect(pgTypeToDataType('date')).toBe('date')
    expect(pgTypeToDataType('timestamptz')).toBe('date')
    expect(pgTypeToDataType('jsonb')).toBe('json')
  })

  it('falls back to string for unknown udt names', () => {
    expect(pgTypeToDataType('citext')).toBe('string')
  })
})

describe('candidateDomains', () => {
  it('offers the full text ladder for strings', () => {
    const values = candidateDomains('string').map((o) => o.value)
    expect(values).toEqual(['Text', 'TextEq', 'TextOrd', 'TextMatch', 'TextSearch'])
  })

  it('offers the integer ladder for numbers', () => {
    const values = candidateDomains('number').map((o) => o.value)
    expect(values).toEqual(['Integer', 'IntegerEq', 'IntegerOrd'])
  })

  it('offers the date ladder for dates', () => {
    const values = candidateDomains('date').map((o) => o.value)
    expect(values).toEqual(['Date', 'DateEq', 'DateOrd'])
  })

  it('offers a single storage-only domain for boolean and json', () => {
    expect(candidateDomains('boolean').map((o) => o.value)).toEqual(['Boolean'])
    expect(candidateDomains('json').map((o) => o.value)).toEqual(['Json'])
  })

  it('gives every option a label and a hint', () => {
    for (const opt of candidateDomains('string')) {
      expect(opt.label.length).toBeGreaterThan(0)
      expect(opt.hint.length).toBeGreaterThan(0)
    }
  })
})

describe('defaultDomain', () => {
  it('defaults to the widest searchable domain per type', () => {
    expect(defaultDomain('string')).toBe('TextSearch')
    expect(defaultDomain('number')).toBe('IntegerOrd')
    expect(defaultDomain('date')).toBe('DateOrd')
    expect(defaultDomain('boolean')).toBe('Boolean')
    expect(defaultDomain('json')).toBe('Json')
  })

  it('always returns a member of that type candidate set', () => {
    for (const dt of ['string', 'number', 'date', 'boolean', 'json'] as const) {
      const values = candidateDomains(dt).map((o) => o.value)
      expect(values).toContain(defaultDomain(dt))
    }
  })
})
