import { DOMAIN_REGISTRY } from '@cipherstash/stack/eql/v3'
import { describe, expect, it } from 'vitest'
import { EXPOSED_DOMAIN_ENTRIES, V3_DOMAIN_META_BY_CODEC_ID } from '../../src/v3/catalog'

describe('FFI catalog invariants (non-structural — pinned)', () => {
  const bareDomains = Object.keys(DOMAIN_REGISTRY)

  it('exposes json as a first-class searchable-JSON domain (ste_vec, no scalar caps)', () => {
    expect(bareDomains.filter((d) => d.includes('json'))).toEqual(['eql_v3_json'])
    const json = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_json@1')
    expect(json?.nativeType).toBe('public.eql_v3_json')
    expect(json?.capabilities.searchableJson).toBe(true)
    expect(json?.capabilities.equality).toBe(false)
    expect(Object.keys(json?.indexes ?? {})).toEqual(['ste_vec'])
    expect(EXPOSED_DOMAIN_ENTRIES.some(([, m]) => m.bareDomain === 'eql_v3_json')).toBe(true)
  })

  it('public.eql_v3_boolean is storage-only (advertises no equality, no indexes)', () => {
    const bool = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_boolean@1')
    expect(bool?.nativeType).toBe('public.eql_v3_boolean')
    expect(bool?.capabilities.equality).toBe(false)
    expect(Object.keys(bool?.indexes ?? {})).toEqual([])
    // there is only one boolean domain (no boolean_eq)
    expect(bareDomains.filter((d) => d.startsWith('eql_v3_boolean'))).toEqual(['eql_v3_boolean'])
  })

  it('the BigInt family IS exposed (base/_eq/_ord), *OrdOre is not', () => {
    const exposedBare = EXPOSED_DOMAIN_ENTRIES.map(([, m]) => m.bareDomain)
    expect(exposedBare).toEqual(
      expect.arrayContaining(['eql_v3_bigint', 'eql_v3_bigint_eq', 'eql_v3_bigint_ord']),
    )
    expect(exposedBare).not.toContain('eql_v3_bigint_ord_ore')
    expect(exposedBare.some((b) => b.endsWith('_ord_ore'))).toBe(false)
  })

  it('plain _ord domains and text_search are OPE-backed; only _ord_ore keeps block-ORE', () => {
    for (const [, meta] of V3_DOMAIN_META_BY_CODEC_ID) {
      const indexKeys = Object.keys(meta.indexes)
      if (meta.bareDomain.endsWith('_ord_ore')) {
        expect(indexKeys).toContain('ore')
        expect(indexKeys).not.toContain('ope')
      } else if (meta.bareDomain.endsWith('_ord') || meta.bareDomain === 'eql_v3_text_search') {
        expect(indexKeys).toContain('ope')
        expect(indexKeys).not.toContain('ore')
      }
    }
  })

  it('native types are public.* while operator SQL is eql_v3.* (schema split not collapsed)', () => {
    for (const [, meta] of V3_DOMAIN_META_BY_CODEC_ID) {
      expect(meta.nativeType.startsWith('public.')).toBe(true)
      expect(meta.nativeType.startsWith('eql_v3.')).toBe(false)
    }
  })
})
