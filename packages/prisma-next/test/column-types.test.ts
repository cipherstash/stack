/**
 * TS contract factories for cipherstash-encrypted columns.
 *
 * v3: one factory per exposed domain, derived 1:1 from the catalog. Each
 * factory takes NO options and returns the domain's concrete descriptor —
 * static codec id, `public.eql_v3_*` native type, and a static
 * `{ castAs, capabilities }` typeParams block — byte-identical to the
 * lowering output of the matching PSL constructor in
 * `src/contract-authoring.ts`.
 *
 * v2: the six pre-rename factories survive verbatim under their `*V2`
 * names (`encryptedStringV2`, …) with their original option arguments and
 * `eql_v2_encrypted` outputs.
 */

import { describe, expect, it } from 'vitest'
import { v3CamelName } from '../src/contract-authoring'
import * as columnTypes from '../src/exports/column-types'
import {
  encryptedBigIntV2,
  encryptedBooleanV2,
  encryptedDateV2,
  encryptedDoubleV2,
  encryptedJsonV2,
  encryptedStringV2,
} from '../src/exports/column-types'
import { EXPOSED_DOMAIN_ENTRIES } from '../src/v3/catalog'

describe('v3 TS factories', () => {
  it('one factory per exposed domain, returning the concrete descriptor', () => {
    for (const [codecId, meta] of EXPOSED_DOMAIN_ENTRIES) {
      const name = v3CamelName(meta.bareDomain)
      const fn = (columnTypes as Record<string, unknown>)[name]
      expect(fn, `missing factory ${name}`).toBeTypeOf('function')
      expect((fn as () => unknown)()).toEqual({
        codecId,
        nativeType: meta.nativeType,
        typeParams: { castAs: meta.castAs, capabilities: meta.capabilities },
      })
    }
  })

  it('bigIntOrd() emits public.eql_v3_bigint_ord with bigint castAs', () => {
    expect(columnTypes.bigIntOrd()).toMatchObject({
      codecId: 'cipherstash/eql-v3/eql_v3_bigint_ord@1',
      nativeType: 'public.eql_v3_bigint_ord',
      typeParams: { castAs: 'bigint' },
    })
  })

  it('textSearch() emits public.eql_v3_text_search with full capabilities', () => {
    expect(columnTypes.textSearch()).toEqual({
      codecId: 'cipherstash/eql-v3/eql_v3_text_search@1',
      nativeType: 'public.eql_v3_text_search',
      typeParams: {
        castAs: 'string',
        capabilities: {
          equality: true,
          orderAndRange: true,
          freeTextSearch: true,
        },
      },
    })
  })

  it('json() emits public.eql_v3_json with searchableJson-only capabilities', () => {
    expect(columnTypes.json()).toEqual({
      codecId: 'cipherstash/eql-v3/eql_v3_json@1',
      nativeType: 'public.eql_v3_json',
      typeParams: {
        castAs: 'json',
        capabilities: {
          equality: false,
          orderAndRange: false,
          freeTextSearch: false,
          searchableJson: true,
        },
      },
    })
  })

  it('returns a FRESH descriptor per invocation — mutating one cannot affect the next', () => {
    // Descriptors flow into caller-owned contract structures; a shared
    // instance would make one caller's mutation alter every later
    // contract (call-order-dependent output). `v3Authored` shallow-copies
    // the capabilities block per call, pinned here.
    const first = columnTypes.textSearch()
    const second = columnTypes.textSearch()
    expect(second).not.toBe(first)
    expect(second.typeParams.capabilities).not.toBe(
      first.typeParams.capabilities,
    )

    // Sabotage the first descriptor (test-only mutability cast — the
    // descriptor type is readonly by design).
    const mutable = first.typeParams.capabilities as {
      equality: boolean
      freeTextSearch: boolean
    }
    mutable.equality = false
    mutable.freeTextSearch = false

    // Neither the already-returned sibling nor a fresh call sees it.
    expect(second.typeParams.capabilities).toEqual({
      equality: true,
      orderAndRange: true,
      freeTextSearch: true,
    })
    expect(columnTypes.textSearch().typeParams.capabilities).toEqual({
      equality: true,
      orderAndRange: true,
      freeTextSearch: true,
    })
  })

  it('exposes no *OrdOre factories and no v3 encryptedString', () => {
    const exported = columnTypes as Record<string, unknown>
    expect(exported['encryptedBigIntOrdOre']).toBeUndefined()
    expect(exported['encryptedTextOrdOre']).toBeUndefined()
    expect(exported['encryptedString']).toBeUndefined()
  })
})

describe('cipherstash column-types (v2 legacy aliases)', () => {
  describe('encryptedStringV2({...}) factory', () => {
    it('produces a ColumnTypeDescriptor with cipherstash/string@1 codec id', () => {
      const descriptor = encryptedStringV2()
      expect(descriptor).toMatchObject({
        codecId: 'cipherstash/string@1',
        nativeType: 'eql_v2_encrypted',
      })
    })

    it('defaults all flags to true when called with no arguments', () => {
      expect(encryptedStringV2()).toEqual({
        codecId: 'cipherstash/string@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          equality: true,
          freeTextSearch: true,
          orderAndRange: true,
        },
      })
    })

    it('defaults all flags to true for an empty options object', () => {
      expect(encryptedStringV2({})).toEqual({
        codecId: 'cipherstash/string@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          equality: true,
          freeTextSearch: true,
          orderAndRange: true,
        },
      })
    })

    it('lets equality be explicitly disabled', () => {
      expect(encryptedStringV2({ equality: false })).toMatchObject({
        typeParams: {
          equality: false,
          freeTextSearch: true,
          orderAndRange: true,
        },
      })
    })

    it('lets freeTextSearch be explicitly disabled', () => {
      expect(encryptedStringV2({ freeTextSearch: false })).toMatchObject({
        typeParams: {
          equality: true,
          freeTextSearch: false,
          orderAndRange: true,
        },
      })
    })

    it('lets orderAndRange be explicitly disabled', () => {
      expect(encryptedStringV2({ orderAndRange: false })).toMatchObject({
        typeParams: {
          equality: true,
          freeTextSearch: true,
          orderAndRange: false,
        },
      })
    })

    it('lets all flags be explicitly disabled (storage-only encryption)', () => {
      expect(
        encryptedStringV2({
          equality: false,
          freeTextSearch: false,
          orderAndRange: false,
        }),
      ).toMatchObject({
        typeParams: {
          equality: false,
          freeTextSearch: false,
          orderAndRange: false,
        },
      })
    })

    it('preserves all flags when explicitly enabled', () => {
      expect(
        encryptedStringV2({
          equality: true,
          freeTextSearch: true,
          orderAndRange: true,
        }),
      ).toMatchObject({
        typeParams: {
          equality: true,
          freeTextSearch: true,
          orderAndRange: true,
        },
      })
    })

    it('returns a structurally equivalent descriptor to the PSL constructor lowering', () => {
      expect(
        encryptedStringV2({
          equality: true,
          freeTextSearch: true,
          orderAndRange: true,
        }),
      ).toEqual({
        codecId: 'cipherstash/string@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          equality: true,
          freeTextSearch: true,
          orderAndRange: true,
        },
      })
    })
  })

  describe('encryptedDoubleV2({...}) factory', () => {
    it('produces a ColumnTypeDescriptor with cipherstash/double@1 codec id', () => {
      expect(encryptedDoubleV2()).toMatchObject({
        codecId: 'cipherstash/double@1',
        nativeType: 'eql_v2_encrypted',
      })
    })

    it('defaults both flags to true when called with no arguments', () => {
      expect(encryptedDoubleV2()).toMatchObject({
        typeParams: { equality: true, orderAndRange: true },
      })
    })

    it('defaults both flags to true for an empty options object', () => {
      expect(encryptedDoubleV2({})).toMatchObject({
        typeParams: { equality: true, orderAndRange: true },
      })
    })

    it('lets equality be explicitly disabled', () => {
      expect(encryptedDoubleV2({ equality: false })).toMatchObject({
        typeParams: { equality: false, orderAndRange: true },
      })
    })

    it('lets orderAndRange be explicitly disabled', () => {
      expect(encryptedDoubleV2({ orderAndRange: false })).toMatchObject({
        typeParams: { equality: true, orderAndRange: false },
      })
    })

    it('lets both flags be explicitly disabled (storage-only encryption)', () => {
      expect(
        encryptedDoubleV2({ equality: false, orderAndRange: false }),
      ).toEqual({
        codecId: 'cipherstash/double@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: { equality: false, orderAndRange: false },
      })
    })
  })

  describe('encryptedBigIntV2({...}) factory', () => {
    it('produces a ColumnTypeDescriptor with cipherstash/bigint@1 codec id', () => {
      expect(encryptedBigIntV2()).toMatchObject({
        codecId: 'cipherstash/bigint@1',
        nativeType: 'eql_v2_encrypted',
      })
    })

    it('defaults both flags to true when called with no arguments', () => {
      expect(encryptedBigIntV2()).toMatchObject({
        typeParams: { equality: true, orderAndRange: true },
      })
    })

    it('lets both flags be explicitly disabled (storage-only encryption)', () => {
      expect(
        encryptedBigIntV2({ equality: false, orderAndRange: false }),
      ).toEqual({
        codecId: 'cipherstash/bigint@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: { equality: false, orderAndRange: false },
      })
    })
  })

  describe('encryptedDateV2({...}) factory', () => {
    it('produces a ColumnTypeDescriptor with cipherstash/date@1 codec id', () => {
      expect(encryptedDateV2()).toMatchObject({
        codecId: 'cipherstash/date@1',
        nativeType: 'eql_v2_encrypted',
      })
    })

    it('defaults both flags to true when called with no arguments', () => {
      expect(encryptedDateV2()).toMatchObject({
        typeParams: { equality: true, orderAndRange: true },
      })
    })

    it('lets both flags be explicitly disabled', () => {
      expect(
        encryptedDateV2({ equality: false, orderAndRange: false }),
      ).toEqual({
        codecId: 'cipherstash/date@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: { equality: false, orderAndRange: false },
      })
    })
  })

  describe('encryptedBooleanV2({...}) factory', () => {
    it('produces a ColumnTypeDescriptor with cipherstash/boolean@1 codec id', () => {
      expect(encryptedBooleanV2()).toMatchObject({
        codecId: 'cipherstash/boolean@1',
        nativeType: 'eql_v2_encrypted',
      })
    })

    it('defaults equality to true when called with no arguments', () => {
      expect(encryptedBooleanV2()).toEqual({
        codecId: 'cipherstash/boolean@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: { equality: true },
      })
    })

    it('lets equality be explicitly disabled', () => {
      expect(encryptedBooleanV2({ equality: false })).toEqual({
        codecId: 'cipherstash/boolean@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: { equality: false },
      })
    })
  })

  describe('encryptedJsonV2({...}) factory', () => {
    it('produces a ColumnTypeDescriptor with cipherstash/json@1 codec id', () => {
      expect(encryptedJsonV2()).toMatchObject({
        codecId: 'cipherstash/json@1',
        nativeType: 'eql_v2_encrypted',
      })
    })

    it('defaults searchableJson to true when called with no arguments', () => {
      expect(encryptedJsonV2()).toEqual({
        codecId: 'cipherstash/json@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: { searchableJson: true },
      })
    })

    it('lets searchableJson be explicitly disabled (storage-only encryption)', () => {
      expect(encryptedJsonV2({ searchableJson: false })).toEqual({
        codecId: 'cipherstash/json@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: { searchableJson: false },
      })
    })
  })
})
