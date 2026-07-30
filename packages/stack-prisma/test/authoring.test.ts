/**
 * Pack-meta authoring contributions for the cipherstash extension.
 *
 * Pinned behaviour:
 *   - Every exposed v3 domain (the catalog minus `*_ord_ore`) gets exactly
 *     one concrete, argument-less `typeConstructor` whose name is the
 *     mechanical `Encrypted<Stem><Suffix>` transform of the bare domain
 *     (`eql_v3_text_search` → `TextSearch`). The output carries the
 *     domain's STATIC codec id, `public.eql_v3_*` native type, and a static
 *     `{ castAs, capabilities }` typeParams block — no options, no
 *     `AuthoringArgRef` nodes.
 *   - `EncryptedString` (unqualified) does not exist — v3 text columns use
 *     the `Text*` family. `Json` (unqualified) is now the
 *     v3 `eql_v3_json_search` domain.
 *
 * Full PSL→ColumnTypeDescriptor lowering is exercised in
 * `test/psl-interpretation*.test.ts`.
 */

import { describe, expect, it } from 'vitest'
import {
  cipherstashAuthoringTypes,
  v3PascalName,
} from '../src/contract-authoring'
import { EXPOSED_DOMAIN_ENTRIES } from '../src/v3/catalog'

type ConstructorView =
  | {
      readonly kind: string
      readonly args?: readonly unknown[]
      readonly output: Record<string, unknown>
    }
  | undefined

// Double cast: the namespace value type is the recursive
// `AuthoringTypeConstructorDescriptor | AuthoringTypeNamespace` union; the
// tests read it as the flat constructor record it actually is.
const ns = cipherstashAuthoringTypes.cipherstash as unknown as Record<
  string,
  ConstructorView
>

describe('cipherstash v3 authoring (concrete per-domain, static descriptors)', () => {
  it('emits exactly one argument-less constructor per exposed domain, matching the catalog values', () => {
    for (const [codecId, meta] of EXPOSED_DOMAIN_ENTRIES) {
      const name = v3PascalName(meta.bareDomain)
      const ctor = ns[name]
      expect(ctor, `missing constructor ${name}`).toBeDefined()
      expect(ctor?.kind).toBe('typeConstructor')
      expect(ctor?.args ?? []).toEqual([])
      expect(ctor?.output).toMatchObject({
        codecId,
        nativeType: meta.nativeType,
        typeParams: { castAs: meta.castAs, capabilities: meta.capabilities },
      })
    }
  })

  it('TextSearch → public.eql_v3_text_search with full capabilities', () => {
    expect(ns.TextSearch?.output).toMatchObject({
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

  it('Boolean → storage-only public.eql_v3_boolean (no equality constructor exists)', () => {
    expect(ns.Boolean?.output).toMatchObject({
      codecId: 'cipherstash/eql-v3/eql_v3_boolean@1',
      nativeType: 'public.eql_v3_boolean',
      typeParams: {
        castAs: 'boolean',
        capabilities: {
          equality: false,
          orderAndRange: false,
          freeTextSearch: false,
        },
      },
    })
    expect(ns.BooleanEq).toBeUndefined()
  })

  it('Json → public.eql_v3_json_search with searchableJson-only capabilities', () => {
    expect(ns.Json?.output).toMatchObject({
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

  it('BigInt family is present (public.eql_v3_bigint*, castAs bigint); no *OrdOre, no v3 String', () => {
    expect(ns.BigInt?.output).toMatchObject({
      nativeType: 'public.eql_v3_bigint',
      typeParams: { castAs: 'bigint' },
    })
    expect(ns.BigIntEq?.output).toMatchObject({
      nativeType: 'public.eql_v3_bigint_eq',
    })
    expect(ns.BigIntOrd?.output).toMatchObject({
      nativeType: 'public.eql_v3_bigint_ord',
    })
    expect(ns.BigIntOrdOre).toBeUndefined()
    expect(ns.IntegerOrdOre).toBeUndefined()
    expect(ns.TextOrdOre).toBeUndefined()
    // v3 text columns use Text*; the unqualified v2 name is gone.
    expect(ns.EncryptedString).toBeUndefined()
  })

  it('the exposed constructor set is exactly the derived v3 names', () => {
    const derived = EXPOSED_DOMAIN_ENTRIES.map(([, meta]) =>
      v3PascalName(meta.bareDomain),
    )
    expect(Object.keys(ns).sort()).toEqual([...derived].sort())
  })
})
