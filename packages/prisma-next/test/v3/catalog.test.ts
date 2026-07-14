import { describe, expect, it } from 'vitest'
import {
  EXPOSED_DOMAIN_ENTRIES,
  envelopeTypeNameForCastAs,
  isOrdOreDomain,
  toV3CodecId,
  V3_CODEC_IDS,
  V3_DOMAIN_META_BY_CODEC_ID,
  V3_FACTORY_BY_NATIVE_TYPE,
} from '../../src/v3/catalog'

describe('v3 catalog derivation', () => {
  it('derives a concrete codec id per domain from the registry key verbatim', () => {
    expect(toV3CodecId('eql_v3_text_search')).toBe('cipherstash/eql-v3/eql_v3_text_search@1')
    expect(toV3CodecId('eql_v3_boolean')).toBe('cipherstash/eql-v3/eql_v3_boolean@1')
  })

  it('records the public.* native type (never eql_v3.*) for text_search with full caps', () => {
    const meta = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_text_search@1')
    expect(meta?.nativeType).toBe('public.eql_v3_text_search')
    expect(meta?.nativeType.startsWith('public.')).toBe(true)
    expect(meta?.castAs).toBe('string')
    expect(meta?.capabilities).toEqual({ equality: true, orderAndRange: true, freeTextSearch: true })
    expect(Object.keys(meta?.indexes ?? {}).sort()).toEqual(['match', 'ope', 'unique'])
  })

  it('marks public.eql_v3_boolean as storage-only (no indexes, all capabilities false)', () => {
    const meta = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_boolean@1')
    expect(meta?.nativeType).toBe('public.eql_v3_boolean')
    expect(meta?.castAs).toBe('boolean')
    expect(meta?.capabilities).toEqual({ equality: false, orderAndRange: false, freeTextSearch: false })
    expect(Object.keys(meta?.indexes ?? {})).toEqual([])
  })

  it('exposes bigint as a first-class family with bigint castAs', () => {
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_bigint@1')?.castAs).toBe('bigint')
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_bigint_ord@1')?.nativeType).toBe(
      'public.eql_v3_bigint_ord',
    )
  })

  it('derives timestamp castAs distinctly from date', () => {
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_timestamp@1')?.castAs).toBe('timestamp')
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_date@1')?.castAs).toBe('date')
  })

  it('exposes json as a first-class searchable-JSON domain (ste_vec index)', () => {
    const meta = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/eql_v3_json@1')
    expect(meta?.nativeType).toBe('public.eql_v3_json')
    expect(meta?.castAs).toBe('json')
    expect(meta?.capabilities).toEqual({
      equality: false,
      orderAndRange: false,
      freeTextSearch: false,
      searchableJson: true,
    })
    expect(Object.keys(meta?.indexes ?? {})).toEqual(['ste_vec'])
    expect(EXPOSED_DOMAIN_ENTRIES.some(([, m]) => m.bareDomain === 'eql_v3_json')).toBe(true)
  })

  it('maps native type back to its concrete factory', () => {
    const factory = V3_FACTORY_BY_NATIVE_TYPE.get('public.eql_v3_integer_ord')
    expect(factory).toBeDefined()
    expect(factory?.('score').getEqlType()).toBe('public.eql_v3_integer_ord')
  })

  it('maps castAs to the envelope type name (bigint distinct from number, json distinct)', () => {
    expect(envelopeTypeNameForCastAs('string')).toBe('EncryptedString')
    expect(envelopeTypeNameForCastAs('number')).toBe('EncryptedNumber')
    expect(envelopeTypeNameForCastAs('bigint')).toBe('EncryptedBigInt')
    expect(envelopeTypeNameForCastAs('date')).toBe('EncryptedDate')
    expect(envelopeTypeNameForCastAs('timestamp')).toBe('EncryptedDate')
    expect(envelopeTypeNameForCastAs('boolean')).toBe('EncryptedBoolean')
    expect(envelopeTypeNameForCastAs('json')).toBe('EncryptedJson')
  })

  it('includes *_ord_ore in the full meta but excludes it from the exposed entries', () => {
    expect(V3_DOMAIN_META_BY_CODEC_ID.has('cipherstash/eql-v3/eql_v3_integer_ord_ore@1')).toBe(true)
    expect(isOrdOreDomain('eql_v3_integer_ord_ore')).toBe(true)
    const exposedBare = new Set(EXPOSED_DOMAIN_ENTRIES.map(([, m]) => m.bareDomain))
    expect([...exposedBare].some((b) => b.endsWith('_ord_ore'))).toBe(false)
    expect(exposedBare.has('eql_v3_integer_ord')).toBe(true)
    expect(exposedBare.has('eql_v3_bigint')).toBe(true)
  })

  it('every codec id is v3-namespaced and unique', () => {
    expect(new Set(V3_CODEC_IDS).size).toBe(V3_CODEC_IDS.length)
    for (const id of V3_CODEC_IDS) expect(id.startsWith('cipherstash/eql-v3/')).toBe(true)
  })
})
