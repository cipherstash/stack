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
 *   - The six pre-existing v2 constructors survive verbatim under their
 *     `*V2` names (`EncryptedStringV2`, …): same optional-object argument
 *     shapes, same `cipherstash/*@1` codec ids, same `eql_v2_encrypted`
 *     native type, same `true`-defaulting `AuthoringArgRef` typeParams.
 *   - `EncryptedString` (unqualified) no longer exists — v3 text columns use
 *     the `Text*` family. `Json` (unqualified) is now the
 *     v3 `eql_v3_json` domain.
 *
 * Full PSL→ColumnTypeDescriptor lowering is exercised in
 * `test/psl-interpretation*.test.ts`.
 */

import { describe, expect, it } from 'vitest'
import {
  cipherstashAuthoringTypes,
  v3PascalName,
} from '../src/contract-authoring'
import cipherstashPack from '../src/exports/pack'
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

  it('Json → public.eql_v3_json with searchableJson-only capabilities', () => {
    expect(ns.Json?.output).toMatchObject({
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

  it('the exposed constructor set is exactly the derived v3 names plus the six *V2 aliases', () => {
    const derived = EXPOSED_DOMAIN_ENTRIES.map(([, meta]) =>
      v3PascalName(meta.bareDomain),
    )
    const v2Aliases = [
      'EncryptedStringV2',
      'EncryptedDoubleV2',
      'EncryptedBigIntV2',
      'EncryptedDateV2',
      'EncryptedBooleanV2',
      'EncryptedJsonV2',
    ]
    expect(Object.keys(ns).sort()).toEqual([...derived, ...v2Aliases].sort())
  })
})

describe('cipherstash pack authoring contributions (v2 legacy aliases)', () => {
  it('exposes cipherstash.EncryptedStringV2 as a namespaced type constructor', () => {
    expect(cipherstashPack.authoring?.type).toMatchObject({
      cipherstash: {
        EncryptedStringV2: {
          kind: 'typeConstructor',
        },
      },
    })
  })

  it('declares a single optional object argument with optional equality + freeTextSearch + orderAndRange boolean properties', () => {
    expect(ns.EncryptedStringV2).toMatchObject({
      kind: 'typeConstructor',
      args: [
        {
          kind: 'object',
          optional: true,
          properties: {
            equality: { kind: 'boolean', optional: true },
            freeTextSearch: { kind: 'boolean', optional: true },
            orderAndRange: { kind: 'boolean', optional: true },
          },
        },
      ],
    })
  })

  it('lowers to ColumnTypeDescriptor with codecId cipherstash/string@1 + nativeType eql_v2_encrypted, defaulting all flags to true', () => {
    expect(ns.EncryptedStringV2?.output).toMatchObject({
      codecId: 'cipherstash/string@1',
      nativeType: 'eql_v2_encrypted',
      typeParams: {
        equality: { kind: 'arg', index: 0, path: ['equality'], default: true },
        freeTextSearch: {
          kind: 'arg',
          index: 0,
          path: ['freeTextSearch'],
          default: true,
        },
        orderAndRange: {
          kind: 'arg',
          index: 0,
          path: ['orderAndRange'],
          default: true,
        },
      },
    })
  })

  it('exposes the storage type registration via pack meta', () => {
    expect(cipherstashPack.types?.storage).toContainEqual({
      typeId: 'cipherstash/string@1',
      familyId: 'sql',
      targetId: 'postgres',
      nativeType: 'eql_v2_encrypted',
    })
  })

  describe('cipherstash.EncryptedDoubleV2', () => {
    it('exposes EncryptedDoubleV2 as a namespaced type constructor', () => {
      expect(cipherstashPack.authoring?.type).toMatchObject({
        cipherstash: { EncryptedDoubleV2: { kind: 'typeConstructor' } },
      })
    })

    it('declares { equality, orderAndRange } booleans, defaulting both to true', () => {
      expect(ns.EncryptedDoubleV2).toMatchObject({
        kind: 'typeConstructor',
        args: [
          {
            kind: 'object',
            optional: true,
            properties: {
              equality: { kind: 'boolean', optional: true },
              orderAndRange: { kind: 'boolean', optional: true },
            },
          },
        ],
      })
      expect(ns.EncryptedDoubleV2?.output).toMatchObject({
        codecId: 'cipherstash/double@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          equality: {
            kind: 'arg',
            index: 0,
            path: ['equality'],
            default: true,
          },
          orderAndRange: {
            kind: 'arg',
            index: 0,
            path: ['orderAndRange'],
            default: true,
          },
        },
      })
    })

    it('registers the cipherstash/double@1 storage type', () => {
      expect(cipherstashPack.types?.storage).toContainEqual({
        typeId: 'cipherstash/double@1',
        familyId: 'sql',
        targetId: 'postgres',
        nativeType: 'eql_v2_encrypted',
      })
    })
  })

  describe('cipherstash.EncryptedBigIntV2', () => {
    it('exposes EncryptedBigIntV2 as a namespaced type constructor', () => {
      expect(cipherstashPack.authoring?.type).toMatchObject({
        cipherstash: { EncryptedBigIntV2: { kind: 'typeConstructor' } },
      })
    })

    it('lowers to ColumnTypeDescriptor with codecId cipherstash/bigint@1, defaulting both flags to true', () => {
      expect(ns.EncryptedBigIntV2?.output).toMatchObject({
        codecId: 'cipherstash/bigint@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          equality: {
            kind: 'arg',
            index: 0,
            path: ['equality'],
            default: true,
          },
          orderAndRange: {
            kind: 'arg',
            index: 0,
            path: ['orderAndRange'],
            default: true,
          },
        },
      })
    })

    it('registers the cipherstash/bigint@1 storage type', () => {
      expect(cipherstashPack.types?.storage).toContainEqual({
        typeId: 'cipherstash/bigint@1',
        familyId: 'sql',
        targetId: 'postgres',
        nativeType: 'eql_v2_encrypted',
      })
    })
  })

  describe('cipherstash.EncryptedDateV2', () => {
    it('exposes EncryptedDateV2 as a namespaced type constructor', () => {
      expect(cipherstashPack.authoring?.type).toMatchObject({
        cipherstash: { EncryptedDateV2: { kind: 'typeConstructor' } },
      })
    })

    it('lowers to ColumnTypeDescriptor with codecId cipherstash/date@1, defaulting both flags to true', () => {
      expect(ns.EncryptedDateV2?.output).toMatchObject({
        codecId: 'cipherstash/date@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          equality: {
            kind: 'arg',
            index: 0,
            path: ['equality'],
            default: true,
          },
          orderAndRange: {
            kind: 'arg',
            index: 0,
            path: ['orderAndRange'],
            default: true,
          },
        },
      })
    })

    it('registers the cipherstash/date@1 storage type', () => {
      expect(cipherstashPack.types?.storage).toContainEqual({
        typeId: 'cipherstash/date@1',
        familyId: 'sql',
        targetId: 'postgres',
        nativeType: 'eql_v2_encrypted',
      })
    })
  })

  describe('cipherstash.EncryptedBooleanV2', () => {
    it('exposes EncryptedBooleanV2 as a namespaced type constructor', () => {
      expect(cipherstashPack.authoring?.type).toMatchObject({
        cipherstash: { EncryptedBooleanV2: { kind: 'typeConstructor' } },
      })
    })

    it('lowers to ColumnTypeDescriptor with codecId cipherstash/boolean@1, defaulting equality to true', () => {
      expect(ns.EncryptedBooleanV2?.output).toMatchObject({
        codecId: 'cipherstash/boolean@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          equality: {
            kind: 'arg',
            index: 0,
            path: ['equality'],
            default: true,
          },
        },
      })
    })

    it('registers the cipherstash/boolean@1 storage type', () => {
      expect(cipherstashPack.types?.storage).toContainEqual({
        typeId: 'cipherstash/boolean@1',
        familyId: 'sql',
        targetId: 'postgres',
        nativeType: 'eql_v2_encrypted',
      })
    })
  })

  describe('cipherstash.EncryptedJsonV2', () => {
    it('exposes EncryptedJsonV2 as a namespaced type constructor', () => {
      expect(cipherstashPack.authoring?.type).toMatchObject({
        cipherstash: { EncryptedJsonV2: { kind: 'typeConstructor' } },
      })
    })

    it('lowers to ColumnTypeDescriptor with codecId cipherstash/json@1, defaulting searchableJson to true', () => {
      expect(ns.EncryptedJsonV2?.output).toMatchObject({
        codecId: 'cipherstash/json@1',
        nativeType: 'eql_v2_encrypted',
        typeParams: {
          searchableJson: {
            kind: 'arg',
            index: 0,
            path: ['searchableJson'],
            default: true,
          },
        },
      })
    })

    it('registers the cipherstash/json@1 storage type', () => {
      expect(cipherstashPack.types?.storage).toContainEqual({
        typeId: 'cipherstash/json@1',
        familyId: 'sql',
        targetId: 'postgres',
        nativeType: 'eql_v2_encrypted',
      })
    })
  })
})
