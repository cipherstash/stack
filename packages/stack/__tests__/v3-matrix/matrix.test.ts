/**
 * Runtime half of the type-driven v3 matrix.
 *
 * A single `it.each` over the `V3_MATRIX` catalog asserts the full per-domain
 * contract for every EQL v3 scalar domain. This SUPERSEDES the hand-rolled
 * `domainCases` loop that previously lived in `schema-v3.test.ts`: the `build()`
 * `toStrictEqual` here is byte-for-byte the same assertion, driven off the
 * shared source of truth. Adding a domain row extends coverage automatically.
 */
import { describe, expect, it } from 'vitest'
import { typedEntries, V3_MATRIX } from './catalog'

describe('eql_v3 type-driven domain matrix (runtime)', () => {
  // `typedEntries` keeps `eqlType` as `EqlV3TypeName` rather than widening to
  // `string`, so the key stays precisely typed through the callback.
  it.each(
    typedEntries(V3_MATRIX),
  )('%s: builder, eqlType, capabilities and build() are consistent', (eqlType, spec) => {
    const col = spec.builder('value')

    expect(col).toBeInstanceOf(spec.ColumnClass)
    expect(col.getName()).toBe('value')
    expect(col.getEqlType()).toBe(eqlType)
    expect(col.getQueryCapabilities()).toStrictEqual(spec.capabilities)
    expect(col.isQueryable()).toBe(
      Object.values(spec.capabilities).some(Boolean),
    )

    // Full-fidelity `build()` check: exactly `{ cast_as, indexes }`, no extra
    // keys — so SDK-facing metadata (eqlType/capabilities) can never leak.
    expect(col.build()).toStrictEqual({
      cast_as: spec.castAs,
      indexes: spec.indexes,
    })
  })
})
