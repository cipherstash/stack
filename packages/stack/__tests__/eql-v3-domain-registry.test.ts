import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { types } from '@/eql/v3'
import {
  DOMAIN_REGISTRY,
  factoryForDomain,
  stripDomainSchema,
  type V3ColumnFactory,
} from '@/eql/v3/domain-registry'

describe('DOMAIN_REGISTRY', () => {
  it('strips the public. schema prefix', () => {
    expect(stripDomainSchema('public.text_search')).toBe('text_search')
    expect(stripDomainSchema('public.integer_ord')).toBe('integer_ord')
    // idempotent for an already-unqualified name
    expect(stripDomainSchema('boolean')).toBe('boolean')
  })

  it('has an entry for every types factory, keyed by the unqualified domain', () => {
    const factories = Object.values(types) as V3ColumnFactory[]
    for (const factory of factories) {
      const eqlType = factory('probe').getEqlType()
      const key = stripDomainSchema(eqlType)
      expect(
        DOMAIN_REGISTRY[key],
        `missing registry entry for ${key}`,
      ).toBeDefined()
      expect(DOMAIN_REGISTRY[key]('c').getEqlType()).toBe(eqlType)
    }
  })

  it('has no registry entry that does not round-trip to its own key', () => {
    for (const [key, factory] of Object.entries(DOMAIN_REGISTRY)) {
      expect(stripDomainSchema(factory('c').getEqlType())).toBe(key)
    }
  })

  it('has exactly as many entries as there are types factories', () => {
    expect(Object.keys(DOMAIN_REGISTRY)).toHaveLength(Object.keys(types).length)
  })

  it('returns undefined for an unknown domain', () => {
    expect(factoryForDomain('not_a_domain')).toBeUndefined()
    expect(factoryForDomain('text_search')).toBe(DOMAIN_REGISTRY.text_search)
  })

  it('PROPERTY: round-trips for any registry key and rejects any non-key', () => {
    const keys = Object.keys(DOMAIN_REGISTRY)
    // Any known key builds a column whose stripped eqlType is that key.
    fc.assert(
      fc.property(fc.constantFrom(...keys), (key) => {
        expect(stripDomainSchema(DOMAIN_REGISTRY[key]('c').getEqlType())).toBe(
          key,
        )
      }),
    )
    // Any arbitrary string that is not a registry key resolves to undefined.
    const keySet = new Set(keys)
    fc.assert(
      fc.property(fc.string(), (s) => {
        fc.pre(!keySet.has(s))
        expect(factoryForDomain(s)).toBeUndefined()
      }),
    )
  })
})

describe('prototype keys are not domains', () => {
  it.each([
    'constructor',
    'toString',
    'valueOf',
    'hasOwnProperty',
    '__proto__',
  ])('factoryForDomain(%s) is undefined', (key) => {
    expect(factoryForDomain(key)).toBeUndefined()
  })

  it('the registry has a null prototype', () => {
    expect(Object.getPrototypeOf(DOMAIN_REGISTRY)).toBeNull()
  })
})
