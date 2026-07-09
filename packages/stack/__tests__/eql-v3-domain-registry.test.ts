import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { types } from '@/eql/v3'
import {
  DOMAIN_REGISTRY,
  factoryForDomain,
  stripDomainSchema,
  type V3ColumnFactory,
} from '@/eql/v3/domain-registry'

/**
 * The EXTERNAL CONTRACT: the SQL domain names this package ships as the
 * `information_schema` query parameter (`introspect.ts`) and matches
 * `domain_name` rows against.
 *
 * Hand-written ON PURPOSE. `DOMAIN_REGISTRY` is derived from
 * `stripDomainSchema(factory(…).getEqlType())`, so any expectation *also*
 * derived from `getEqlType()` only measures the source against itself: corrupt
 * a domain constant in `columns.ts` and the registry silently re-keys, the SQL
 * param ships the wrong name, real columns are misclassified as unmodelled —
 * and a derived assertion still passes. This literal list is the only thing
 * that fails. Do not compute it.
 */
const EXPECTED_DOMAIN_KEYS = [
  'integer',
  'integer_eq',
  'integer_ord_ore',
  'integer_ord',
  'smallint',
  'smallint_eq',
  'smallint_ord_ore',
  'smallint_ord',
  'bigint',
  'bigint_eq',
  'bigint_ord_ore',
  'bigint_ord',
  'date',
  'date_eq',
  'date_ord_ore',
  'date_ord',
  'timestamp',
  'timestamp_eq',
  'timestamp_ord_ore',
  'timestamp_ord',
  'numeric',
  'numeric_eq',
  'numeric_ord_ore',
  'numeric_ord',
  'text',
  'text_eq',
  'text_match',
  'text_ord_ore',
  'text_ord',
  'text_search',
  'boolean',
  'real',
  'real_eq',
  'real_ord_ore',
  'real_ord',
  'double',
  'double_eq',
  'double_ord_ore',
  'double_ord',
] as const

describe('DOMAIN_REGISTRY', () => {
  it('strips the public. schema prefix', () => {
    expect(stripDomainSchema('public.text_search')).toBe('text_search')
    expect(stripDomainSchema('public.integer_ord')).toBe('integer_ord')
    // idempotent for an already-unqualified name
    expect(stripDomainSchema('boolean')).toBe('boolean')
  })

  it('keys are exactly the expected SQL domain names', () => {
    expect(Object.keys(DOMAIN_REGISTRY).sort()).toEqual(
      [...EXPECTED_DOMAIN_KEYS].sort(),
    )
  })

  it('maps each expected domain to a factory that builds that domain', () => {
    for (const key of EXPECTED_DOMAIN_KEYS) {
      const factory = factoryForDomain(key)
      expect(factory, `missing registry entry for ${key}`).toBeDefined()
      expect((factory as V3ColumnFactory)('c').getEqlType()).toBe(
        `public.${key}`,
      )
    }
  })

  // The derivation drops an entry rather than throwing only if two factories
  // collide on one key; a short registry is that collision.
  it('derives one entry per types factory, with no key collisions', () => {
    expect(Object.keys(DOMAIN_REGISTRY)).toHaveLength(Object.keys(types).length)
  })

  it('returns undefined for an unknown domain', () => {
    expect(factoryForDomain('not_a_domain')).toBeUndefined()
    expect(factoryForDomain('text_search')).toBe(DOMAIN_REGISTRY.text_search)
  })

  it('PROPERTY: rejects any string that is not a registry key', () => {
    const keySet = new Set(Object.keys(DOMAIN_REGISTRY))
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
