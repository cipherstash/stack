import {
  deferredForFamily,
  domainsForFamily,
  eqlTypeSlug,
  FAMILY_NAMES,
  isCovered,
  typedEntries,
  V3_MATRIX,
} from '@cipherstash/test-kit'
import { describe, expect, it } from 'vitest'

/**
 * The integration suites are split one file per plaintext family, and each file
 * asks `domainsForFamily(name)` which domains it owns. Nothing in that lookup
 * forces the families to COVER the catalog: add a domain whose slug matches no
 * family prefix (`interval_ord`, say) and it simply belongs to no file — the
 * suites stay green while the domain goes untested.
 *
 * The catalog's `satisfies Record<…>` cannot catch that; it only forces a ROW to
 * exist. These tests close the gap by asserting the families partition the
 * catalog: every domain lands in exactly one family, and covered + deferred
 * accounts for all of them.
 */
describe('test-kit families partition the v3 catalog', () => {
  const bare = (eqlType: string) => eqlTypeSlug(eqlType).replace(/^eql_v3_/, '')
  const allBare = typedEntries(V3_MATRIX).map(([eqlType]) => bare(eqlType))

  it('assigns every covered domain to exactly one family', () => {
    const owners = new Map<string, string[]>()
    for (const family of FAMILY_NAMES) {
      for (const domain of domainsForFamily(family)) {
        owners.set(domain.bare, [...(owners.get(domain.bare) ?? []), family])
      }
    }

    const multiplyOwned = [...owners].filter(([, fams]) => fams.length > 1)
    expect(multiplyOwned).toEqual([])

    const coveredBare = typedEntries(V3_MATRIX)
      .filter(([, spec]) => isCovered(spec))
      .map(([eqlType]) => bare(eqlType))
      .sort()

    expect([...owners.keys()].sort()).toEqual(coveredBare)
  })

  it('accounts for every catalog domain as covered or deferred', () => {
    const covered = FAMILY_NAMES.flatMap((f) =>
      domainsForFamily(f).map((d) => d.bare),
    )
    const deferred = FAMILY_NAMES.flatMap((f) =>
      deferredForFamily(f).map((d) => d.bare),
    )

    expect([...covered, ...deferred].sort()).toEqual([...allBare].sort())
  })

  it('defers the block-ORE domains and json, each with a reason', () => {
    const deferred = FAMILY_NAMES.flatMap((f) => deferredForFamily(f))

    expect(deferred.map((d) => d.bare).sort()).toEqual([
      'bigint_ord_ore',
      'date_ord_ore',
      'double_ord_ore',
      'integer_ord_ore',
      'json',
      'numeric_ord_ore',
      'real_ord_ore',
      'smallint_ord_ore',
      'text_ord_ore',
      'timestamp_ord_ore',
    ])
    // ORE domains defer for the superuser-only opclass; json defers because it
    // is queried by containment, not the scalar op-matrix (covered by dedicated
    // suites — see catalog reason).
    for (const { bare, reason } of deferred) {
      expect(reason).toMatch(bare === 'json' ? /containment/ : /superuser-only/)
    }
  })

  it('never hands a family a domain from a neighbouring prefix', () => {
    // `date` must not claim `timestamp_ord`, and `integer` must not claim
    // `smallint`. The prefix match is anchored on `_` or end-of-string; a naive
    // `startsWith` would fail this.
    expect(domainsForFamily('date').map((d) => d.bare)).toEqual([
      'date',
      'date_eq',
      'date_ord',
    ])
    expect(domainsForFamily('text').map((d) => d.bare)).toEqual([
      'text',
      'text_eq',
      'text_match',
      'text_ord',
      'text_search',
    ])
  })
})
