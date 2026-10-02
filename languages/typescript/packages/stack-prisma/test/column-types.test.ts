/**
 * TS contract factories for cipherstash-encrypted columns.
 *
 * v3: one factory per exposed domain, derived 1:1 from the catalog. Each
 * factory takes NO options and returns the domain's concrete descriptor —
 * static codec id, `public.eql_v3_*` native type, and a static
 * `{ castAs, capabilities }` typeParams block — byte-identical to the
 * lowering output of the matching PSL constructor in
 * `src/contract-authoring.ts`.
 */

import { describe, expect, it } from 'vitest'
import { v3CamelName } from '../src/contract-authoring'
import * as columnTypes from '../src/exports/column-types'
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

  it('json() emits public.eql_v3_json_search with searchableJson-only capabilities', () => {
    expect(columnTypes.json()).toEqual({
      codecId: 'cipherstash/eql-v3/eql_v3_json_search@1',
      nativeType: 'public.eql_v3_json_search',
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

  it('exposes no *OrdOre factories and no v3 string factory', () => {
    const exported = columnTypes as Record<string, unknown>
    expect(exported['bigIntOrdOre']).toBeUndefined()
    expect(exported['textOrdOre']).toBeUndefined()
    // v3 text uses `text`/`textEq`/`textSearch`/… — there is no `string`.
    expect(exported['string']).toBeUndefined()
  })
})
