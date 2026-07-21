/**
 * Property-based coverage (fast-check) for the v3 surface — the
 * cross-cutting invariants the example-based suites pin pointwise:
 *
 *   1. WIRE: `v3FromDriver(v3ToDriver(x))` is identity over JSON
 *      documents (plain-JSONB wire), object passthrough is by
 *      reference, null/undefined lower to NULL, and stray bigints in a
 *      malformed envelope serialise as decimal strings instead of
 *      throwing.
 *   2. REDACTION: no coercion/serialisation path of an envelope ever
 *      renders the plaintext — every path is the `[REDACTED]` string or
 *      the `$encrypted*: "<opaque>"` placeholder.
 *   3. AUTHORING: constructor ↔ domain totality/bijectivity — every
 *      exposed catalog domain has exactly one authoring constructor
 *      whose descriptor equals the catalog values, no constructor maps
 *      off-catalog, and the pascal/camel name transforms agree and are
 *      injective.
 *   4. GATING: capability flags are exactly equivalent to the domain's
 *      FFI index set (equality ⇔ unique|ope|ore, orderAndRange ⇔
 *      ope|ore, freeTextSearch ⇔ match, searchableJson ⇔ ste_vec), the
 *      trait derivation is a bijection with the flags, and every
 *      (domain × operator) pair is TOTAL: it either lowers to the
 *      canonical `::eql_v3.query_<domain>` template or throws
 *      `EncryptionOperatorError` — decided exactly by the capability.
 *      The finite domain×operator grid is swept exhaustively (stronger
 *      than sampling); the infinite spaces use fast-check.
 *   5. DERIVATION: contract column → `deriveStackSchemasV3` →
 *      derived column's domain identity equals the original for every
 *      codec id (including the authoring-unexposed `*_ord_ore`
 *      decode-side domains); foreign codec ids never derive a table.
 *
 * No property talks to the network; every case is pure lowering /
 * catalog / wire code, so the suite stays deterministic-fast at
 * fast-check's default numRuns.
 */

import {
  type AnyExpression,
  OperationExpr,
} from '@prisma-next/sql-relational-core/ast'
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import {
  cipherstashAuthoringTypes,
  v3CamelName,
  v3PascalName,
} from '../../src/contract-authoring'
import { EncryptedJson } from '../../src/execution/envelope-json'
import {
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
  CIPHERSTASH_TRAIT_SEARCHABLE_JSON,
  isCipherstashV3CodecId,
  v3TraitsForCapabilities,
} from '../../src/extension-metadata/constants-v3'
import {
  EXPOSED_DOMAIN_ENTRIES,
  V3_CODEC_IDS,
  V3_DOMAIN_META_BY_CODEC_ID,
  V3_FACTORY_BY_NATIVE_TYPE,
  type V3CastAs,
  type V3DomainMeta,
} from '../../src/v3/catalog'
import { deriveStackSchemasV3 } from '../../src/v3/derive-schemas-v3'
import { EncryptedNumber } from '../../src/v3/envelope-number'
import {
  EncryptionOperatorError,
  eqlAsc,
  eqlDesc,
} from '../../src/v3/operators-v3'
import { v3FromDriver, v3ToDriver } from '../../src/v3/wire-v3'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
  TABLE,
} from './operator-lowering-v3.helpers'

const ALL_DOMAIN_ENTRIES: ReadonlyArray<readonly [string, V3DomainMeta]> = [
  ...V3_DOMAIN_META_BY_CODEC_ID.entries(),
]

const EQL_V3_PREFIX = 'eql_v3_'

/** `eql_v3_text_search` → `eql_v3.query_text_search` (regular domains). */
function expectedQueryCast(meta: V3DomainMeta): string {
  return `eql_v3.query_${meta.bareDomain.slice(EQL_V3_PREFIX.length)}`
}

/** Unwrap the lowering template of an operator-built AST node. */
function templateOf(expr: AnyExpression): string {
  expect(expr).toBeInstanceOf(OperationExpr)
  // SqlLoweringSpec's 'function' strategy variant carries the template.
  const { template } = (expr as OperationExpr).lowering as { template: string }
  expect(typeof template).toBe('string')
  return template
}

/**
 * Deep-map `-0` to `0`. JSONB **text** cannot carry the sign of a
 * negative zero (`JSON.stringify(-0)` is `"0"` per ECMA-262), so the
 * wire round-trip is identity up to this one JSON-semantics
 * normalization — `fc.jsonValue()` does generate `-0`, and vitest's
 * `toEqual` distinguishes it via `Object.is`.
 */
function withoutNegativeZero(value: unknown): unknown {
  if (typeof value === 'number') return Object.is(value, -0) ? 0 : value
  if (Array.isArray(value)) return value.map(withoutNegativeZero)
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, withoutNegativeZero(v)]),
    )
  }
  return value
}

describe('property: JSONB wire round-trip (v3ToDriver / v3FromDriver)', () => {
  it('v3FromDriver(v3ToDriver(x)) deep-equals x for arbitrary JSON documents', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (x) => {
        expect(v3FromDriver(v3ToDriver(x))).toEqual(withoutNegativeZero(x))
      }),
    )
  })

  it('null/undefined lower to NULL on encode and are preserved on decode', () => {
    expect(v3ToDriver(null)).toBeNull()
    expect(v3ToDriver(undefined)).toBeNull()
    expect(v3FromDriver(null)).toBeNull()
    expect(v3FromDriver(undefined)).toBeUndefined()
  })

  it('pre-parsed jsonb objects pass through decode by reference (pg drivers that parse jsonb)', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.array(fc.jsonValue()),
          fc.dictionary(fc.string(), fc.jsonValue()),
        ),
        (obj) => {
          expect(v3FromDriver(obj)).toBe(obj)
        },
      ),
    )
  })

  it('stray bigints anywhere in a payload encode as decimal strings instead of throwing', () => {
    // A well-formed envelope never carries a bigint (plaintext is
    // encrypted to ciphertext strings first), but the wire layer's
    // bigintSafeReplacer must keep a malformed one from crashing
    // JSON.stringify — pinned here across nesting positions.
    fc.assert(
      fc.property(fc.bigInt(), fc.jsonValue(), (b, doc) => {
        const decoded = v3FromDriver(
          v3ToDriver({ stray: b, nested: [b, { deep: b }], doc }),
        )
        expect(decoded).toEqual({
          stray: b.toString(),
          nested: [b.toString(), { deep: b.toString() }],
          doc: withoutNegativeZero(doc),
        })
      }),
    )
  })
})

describe('property: [REDACTED] invariant (no coercion path leaks plaintext)', () => {
  it('EncryptedNumber renders the opaque placeholder / [REDACTED] for every double', () => {
    fc.assert(
      fc.property(fc.double({ noNaN: true }), (n) => {
        const env = EncryptedNumber.from(n)
        expect(JSON.stringify(env)).toBe('{"$encryptedNumber":"<opaque>"}')
        expect(String(env)).toBe('[REDACTED]')
        expect(env.valueOf()).toBe('[REDACTED]')
        expect(`${env}`).not.toContain(String(n))
      }),
    )
  })

  it('EncryptedJson serialises to its placeholder for every JSON document, nested included', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (doc) => {
        const env = EncryptedJson.from(doc)
        expect(JSON.stringify(env)).toBe('{"$encryptedJson":"<opaque>"}')
        expect(JSON.stringify({ payload: env })).toBe(
          '{"payload":{"$encryptedJson":"<opaque>"}}',
        )
        expect(String(env)).toBe('[REDACTED]')
      }),
    )
  })
})

describe('property: constructor ↔ domain totality (authoring namespace)', () => {
  // Structural view over the namespace: every descriptor is a
  // typeConstructor with a static output block. The declared
  // `AuthoringTypeNamespace` value type is a descriptor/namespace union,
  // so the narrowing goes through `unknown` (test-only view cast).
  const ns = cipherstashAuthoringTypes.cipherstash as unknown as Record<
    string,
    {
      output: {
        codecId: string
        nativeType: string
        typeParams: { castAs: V3CastAs; capabilities: unknown }
      }
    }
  >
  it('every exposed domain has exactly one constructor whose descriptor equals the catalog values', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...EXPOSED_DOMAIN_ENTRIES),
        ([codecId, meta]) => {
          const ctor = ns[v3PascalName(meta.bareDomain)]
          expect(ctor).toBeDefined()
          expect(ctor?.output.codecId).toBe(codecId)
          expect(ctor?.output.nativeType).toBe(meta.nativeType)
          expect(meta.nativeType.startsWith('public.')).toBe(true)
          expect(ctor?.output.typeParams.castAs).toBe(meta.castAs)
          // toEqual treats an absent searchableJson key as equal to an
          // undefined one, matching capabilitiesTemplate's omission.
          expect(ctor?.output.typeParams.capabilities).toEqual(
            meta.capabilities,
          )
        },
      ),
    )
  })

  it('no constructor maps off-catalog and the counts agree', () => {
    const validNames = new Set(
      EXPOSED_DOMAIN_ENTRIES.map(([, m]) => v3PascalName(m.bareDomain)),
    )
    for (const name of Object.keys(ns)) {
      expect(validNames.has(name), `constructor ${name} is off-catalog`).toBe(
        true,
      )
    }
    expect(Object.keys(ns)).toHaveLength(EXPOSED_DOMAIN_ENTRIES.length)
  })

  it('name transforms are injective and pascal/camel agree modulo first-letter case', () => {
    const pascalNames = EXPOSED_DOMAIN_ENTRIES.map(([, m]) =>
      v3PascalName(m.bareDomain),
    )
    expect(new Set(pascalNames).size).toBe(EXPOSED_DOMAIN_ENTRIES.length)
    fc.assert(
      fc.property(fc.constantFrom(...EXPOSED_DOMAIN_ENTRIES), ([, meta]) => {
        const pascal = v3PascalName(meta.bareDomain)
        const camel = v3CamelName(meta.bareDomain)
        // v3 constructor names dropped the `Encrypted` prefix (the
        // `cipherstash.` namespace disambiguates); they are PascalCase.
        expect(pascal.startsWith('Encrypted')).toBe(false)
        expect(pascal.charAt(0)).toBe(pascal.charAt(0).toUpperCase())
        expect(camel).toBe(
          `${pascal.charAt(0).toLowerCase()}${pascal.slice(1)}`,
        )
      }),
    )
  })
})

describe('property: capability gating', () => {
  it('capability flags are exactly the FFI index set for every domain', () => {
    // GA index split: `unique` (HMAC equality), `ope`/`ore` (ordering —
    // ordered domains also answer equality via their order term),
    // `match` (bloom free-text), `ste_vec` (searchable JSON).
    fc.assert(
      fc.property(fc.constantFrom(...ALL_DOMAIN_ENTRIES), ([, meta]) => {
        const has = (key: string) => key in meta.indexes
        expect(meta.capabilities.equality).toBe(
          has('unique') || has('ope') || has('ore'),
        )
        expect(meta.capabilities.orderAndRange).toBe(has('ope') || has('ore'))
        expect(meta.capabilities.freeTextSearch).toBe(has('match'))
        expect(meta.capabilities.searchableJson === true).toBe(has('ste_vec'))
        // A domain never carries both ordering flavours.
        expect(has('ope') && has('ore')).toBe(false)
      }),
    )
  })

  it('trait derivation is a bijection with the capability flags (total over arbitrary flag sets)', () => {
    fc.assert(
      fc.property(
        fc.record({
          equality: fc.boolean(),
          orderAndRange: fc.boolean(),
          freeTextSearch: fc.boolean(),
          searchableJson: fc.option(fc.boolean(), { nil: undefined }),
        }),
        (caps) => {
          const traits = v3TraitsForCapabilities(caps)
          expect(traits.includes(CIPHERSTASH_TRAIT_EQUALITY)).toBe(
            caps.equality,
          )
          expect(traits.includes(CIPHERSTASH_TRAIT_ORDER_AND_RANGE)).toBe(
            caps.orderAndRange,
          )
          expect(traits.includes(CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH)).toBe(
            caps.freeTextSearch,
          )
          expect(traits.includes(CIPHERSTASH_TRAIT_SEARCHABLE_JSON)).toBe(
            caps.searchableJson === true,
          )
          expect(new Set(traits).size).toBe(traits.length)
        },
      ),
    )
  })
})

describe('property: operator-gating totality (every domain × every operator)', () => {
  const SAMPLE_PLAINTEXT: Record<V3CastAs, unknown> = {
    string: 'alice',
    number: 42,
    bigint: 42n,
    date: new Date('2026-01-02T00:00:00Z'),
    timestamp: new Date('2026-01-02T03:04:05Z'),
    boolean: true,
    json: { role: 'admin' }, // non-empty: the match-all {} needle is rejected
  }

  type CapabilityKey = keyof V3DomainMeta['capabilities']
  const OPERATOR_CASES: ReadonlyArray<{
    method: string
    capability: CapabilityKey
    args: (value: unknown) => unknown[]
  }> = [
    { method: 'eqlEq', capability: 'equality', args: (v) => [v] },
    { method: 'eqlNeq', capability: 'equality', args: (v) => [v] },
    {
      method: 'eqlIn',
      capability: 'equality',
      args: (v) => [[v, v]],
    },
    {
      method: 'eqlNotIn',
      capability: 'equality',
      args: (v) => [[v]],
    },
    { method: 'eqlGt', capability: 'orderAndRange', args: (v) => [v] },
    { method: 'eqlGte', capability: 'orderAndRange', args: (v) => [v] },
    { method: 'eqlLt', capability: 'orderAndRange', args: (v) => [v] },
    { method: 'eqlLte', capability: 'orderAndRange', args: (v) => [v] },
    {
      method: 'eqlBetween',
      capability: 'orderAndRange',
      args: (v) => [v, v],
    },
    {
      method: 'eqlNotBetween',
      capability: 'orderAndRange',
      args: (v) => [v, v],
    },
    // No negated match case: the v3 registry deliberately exposes no
    // `eqlNotMatch` (bloom negation false-negatives; PR #655 review).
    {
      method: 'eqlMatch',
      capability: 'freeTextSearch',
      args: (v) => [v],
    },
    {
      method: 'eqlJsonContains',
      capability: 'searchableJson',
      args: (v) => [v],
    },
  ]

  it('each pair either lowers with the canonical query cast or throws EncryptionOperatorError, decided by the capability', () => {
    // The (domain × operator) grid is finite and small (40 × 12), so it
    // is swept exhaustively — strictly stronger than random sampling.
    for (const [codecId, meta] of ALL_DOMAIN_ENTRIES) {
      for (const opCase of OPERATOR_CASES) {
        const allowed = meta.capabilities[opCase.capability] === true
        const label = `${meta.bareDomain} × ${opCase.method}`
        const call = () =>
          callOperator(
            getOperator(opCase.method),
            columnAccessorV3(TABLE, 'c', codecId),
            ...opCase.args(SAMPLE_PLAINTEXT[meta.castAs]),
          )
        if (!allowed) {
          expect(call, label).toThrow(EncryptionOperatorError)
          continue
        }
        // Totality: a gate-passing domain always has a query cast — the
        // internal-invariant throw in requireQueryCast must be dead code.
        const template = templateOf(call())
        const cast =
          opCase.method === 'eqlJsonContains'
            ? 'eql_v3.query_jsonb'
            : expectedQueryCast(meta)
        expect(template, label).toContain(`::${cast}`)
      }
    }
  })

  it('ordering helpers succeed iff orderAndRange, extracting ord_term_ore exactly on block-ORE domains', () => {
    for (const [codecId, meta] of ALL_DOMAIN_ENTRIES) {
      const col = () => columnAccessorV3(TABLE, 'c', codecId)
      if (!meta.capabilities.orderAndRange) {
        expect(() => eqlAsc(col()), meta.bareDomain).toThrow(
          EncryptionOperatorError,
        )
        expect(() => eqlDesc(col()), meta.bareDomain).toThrow(
          EncryptionOperatorError,
        )
        continue
      }
      const fn = 'ore' in meta.indexes ? 'ord_term_ore' : 'ord_term'
      const asc = eqlAsc(col())
      const desc = eqlDesc(col())
      expect(asc.dir).toBe('asc')
      expect(desc.dir).toBe('desc')
      expect(templateOf(asc.expr), meta.bareDomain).toBe(
        `eql_v3.${fn}({{self}})`,
      )
      expect(templateOf(desc.expr), meta.bareDomain).toBe(
        `eql_v3.${fn}({{self}})`,
      )
    }
  })
})

describe('property: derivation round-trip (contract → deriveStackSchemasV3)', () => {
  function contractFor(codecId: string, nativeType: string) {
    return {
      storage: {
        namespaces: {
          public: {
            entries: {
              table: { user: { columns: { c: { codecId, nativeType } } } },
            },
          },
        },
      },
    }
  }

  it('every codec id derives a column whose domain identity equals the original', () => {
    fc.assert(
      fc.property(fc.constantFrom(...ALL_DOMAIN_ENTRIES), ([codecId, meta]) => {
        const tables = deriveStackSchemasV3(
          contractFor(codecId, meta.nativeType),
        )
        expect(tables).toHaveLength(1)
        const table = tables[0]
        expect(table?.tableName).toBe('user')
        const col = Object.values(table?.columnBuilders ?? {})[0]
        expect((col as { getEqlType(): string }).getEqlType()).toBe(
          meta.nativeType,
        )
        const builtColumn = table?.build().columns.c
        expect(builtColumn?.cast_as).toBe(meta.castAs)
        expect(Object.keys(builtColumn?.indexes ?? {}).sort()).toEqual(
          Object.keys(meta.indexes).sort(),
        )
      }),
    )
  })

  it('(codec id) ⟺ (public.* domain) is bijective through the factory map', () => {
    expect(V3_FACTORY_BY_NATIVE_TYPE.size).toBe(V3_CODEC_IDS.length)
    fc.assert(
      fc.property(fc.constantFrom(...ALL_DOMAIN_ENTRIES), ([, meta]) => {
        const factory = V3_FACTORY_BY_NATIVE_TYPE.get(meta.nativeType)
        expect(factory).toBeDefined()
        expect(factory?.('c').getEqlType()).toBe(meta.nativeType)
      }),
    )
  })

  it('arbitrary non-cipherstash codec ids never derive a table', () => {
    const known = new Set(V3_CODEC_IDS)
    fc.assert(
      fc.property(fc.string(), (codecId) => {
        fc.pre(!known.has(codecId))
        expect(isCipherstashV3CodecId(codecId)).toBe(false)
        expect(
          deriveStackSchemasV3(contractFor(codecId, 'public.eql_v3_text')),
        ).toHaveLength(0)
      }),
    )
  })
})
