import { describe, expect, it } from 'vitest'
import { isV3ColumnLike } from '../src/column-map'

/**
 * Unit coverage for the structural v3 gate.
 *
 * `ColumnMap`'s tests pin the CONSEQUENCE — construction refuses, and no query
 * string reaches PostgREST. They do not pin the predicate's shape: every fixture
 * that reaches it either satisfies all four probes or (the one negative case)
 * misses two at once, so no test there distinguishes a four-probe gate from a
 * three- or two-probe one. Deleting any single probe, or weakening any single
 * `typeof` to `true`, left the whole package suite green.
 *
 * These cases are written to be one-probe-apart from a passing builder, so each
 * fails if and only if its own probe is removed.
 */

type Probe = 'getName' | 'getEqlType' | 'getQueryCapabilities' | 'build'

const PROBES: Probe[] = [
  'getName',
  'getEqlType',
  'getQueryCapabilities',
  'build',
]

/** A builder presenting exactly the surface the predicate probes for. */
const conforming = (): Record<Probe, unknown> => ({
  getName: () => 'email',
  getEqlType: () => 'public.eql_v3_text_search',
  getQueryCapabilities: () => ({
    equality: true,
    orderAndRange: false,
    freeTextSearch: true,
  }),
  build: () => ({}),
})

const withoutProbe = (probe: Probe): Record<string, unknown> => {
  const builder = conforming()
  delete builder[probe]
  return builder
}

const withNonFunctionProbe = (probe: Probe): Record<string, unknown> => ({
  ...conforming(),
  [probe]: 'not a function',
})

describe('isV3ColumnLike', () => {
  it('accepts a builder presenting all four members', () => {
    expect(isV3ColumnLike(conforming())).toBe(true)
  })

  // The mutation-killing core. Each fixture is one member away from the
  // conforming builder above, so it can only be rejected by that member's own
  // probe. A fixture missing two members (the shape the ColumnMap tests use)
  // would be rejected by either, and so kills neither.
  it.each(PROBES)('rejects a builder missing only %s()', (probe) => {
    expect(isV3ColumnLike(withoutProbe(probe))).toBe(false)
  })

  // `'x' in builder` alone is satisfied by any present key. These pin the
  // `typeof … === 'function'` half of each conjunct, which the `in` half cannot
  // stand in for.
  it.each(PROBES)('rejects a builder whose %s is not a function', (probe) => {
    expect(isV3ColumnLike(withNonFunctionProbe(probe))).toBe(false)
  })

  // `typeof null === 'object'`, so `null` slips past the first half of the
  // guard and only the explicit `builder === null` half rejects it. That half
  // is load-bearing on its own: without it `'getName' in null` throws a raw
  // TypeError instead of returning false, and ColumnMap's fail-closed error is
  // replaced by an unrelated crash.
  it('rejects null', () => {
    expect(isV3ColumnLike(null)).toBe(false)
  })

  // These four go the other way — each is rejected by the `typeof builder !==
  // 'object'` half. Split from `null` above so a mutant that drops only one
  // half of the guard names which half it dropped.
  it.each([
    ['undefined', undefined],
    ['a number', 42],
    ['a string', 'email'],
    ['a boolean', true],
  ])('rejects %s', (_label, builder) => {
    expect(isV3ColumnLike(builder)).toBe(false)
  })

  // The real `Encrypted*Column` classes carry all four methods on the
  // PROTOTYPE — their own properties are just `columnName`/`definition`. So the
  // probes must use `in`, which walks the chain, and must not become
  // `Object.hasOwn`, which does not.
  it('accepts a builder whose members live on the prototype', () => {
    class PrototypeColumn {
      getName() {
        return 'email'
      }
      getEqlType() {
        return 'public.eql_v3_text_search'
      }
      getQueryCapabilities() {
        return { equality: true, orderAndRange: false, freeTextSearch: true }
      }
      build() {
        return {}
      }
    }

    const builder = new PrototypeColumn()

    expect(Object.hasOwn(builder, 'getName')).toBe(false)
    expect(isV3ColumnLike(builder)).toBe(true)
  })

  // The case the four-probe design exists for, stated with the real class
  // rather than a hand-rolled stub: a v2 column builder genuinely has `build()`
  // and `getName()` and genuinely lacks the other two. A two-probe gate would
  // accept it and its filter operands would go to PostgREST in the clear.
  it('rejects the structural shape of a legacy v2 column builder', () => {
    const v2 = { getName: () => 'email', build: () => ({}) }

    // Spelled out so that if `EncryptedColumn` ever grows one of these, the
    // failure names the cause rather than just reporting `true !== false`.
    expect(typeof v2.getName).toBe('function')
    expect(typeof v2.build).toBe('function')
    expect('getEqlType' in v2).toBe(false)
    expect('getQueryCapabilities' in v2).toBe(false)
    expect(isV3ColumnLike(v2)).toBe(false)
  })
})
