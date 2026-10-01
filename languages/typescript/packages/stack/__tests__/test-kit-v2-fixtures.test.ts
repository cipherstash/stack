import {
  V3_MATRIX,
  v2FixturePlan,
  v2OpeIndexedDomains,
  v2UndeclaredCastAs,
} from '@cipherstash/test-kit'
import { describe, expect, it } from 'vitest'

/**
 * The accounting half of the v2 fixture matrix — unit-tested, deliberately.
 *
 * These three checks are the mechanism that keeps the v2 read matrix honest:
 * they turn "some domains were quietly skipped" into a red build. They are pure
 * functions over `V3_MATRIX` — no network, no credentials, no FFI.
 *
 * They are duplicated here, rather than left only in
 * `integration/shared/v2-decrypt-compat.integration.test.ts` which consumes the
 * same plan, because that suite fails hard without live CipherStash credentials
 * (`requireIntegrationEnv`) and will not even collect without them. A guard whose
 * whole purpose is to fire when someone adds a domain is worth little if it only
 * fires for the subset of contributors holding integration credentials — that is
 * the silent-skip failure mode this repo already guards against elsewhere (see
 * the `CS_IT_SUITE` glob guard in `integration/vitest.config.ts`). Here they run
 * in `pnpm test`, for everyone, on every domain change.
 *
 * Sibling precedent: `test-kit-families.test.ts` / `test-kit-env.test.ts`.
 */
describe('v2 fixture plan accounting', () => {
  const plan = v2FixturePlan()

  it('accounts for every catalog domain as either minted or deferred', () => {
    const accounted = [
      ...plan.domains.map((domain) => domain.eqlType),
      ...plan.deferred.map((domain) => domain.eqlType),
    ].sort()
    // The partition IS the coverage mechanism: a domain in neither set has been
    // dropped, and one in both would be counted twice.
    expect(accounted).toEqual(Object.keys(V3_MATRIX).sort())
    expect(plan.domains.length).toBeGreaterThan(0)
    for (const { eqlType, reason } of plan.deferred) {
      expect(reason, `${eqlType} is deferred with no reason`).not.toBe('')
    }
  })

  /**
   * The exclusions are hand-written so a NEW domain defaults to covered and
   * fails loudly. This stops that list drifting from the rule it encodes: the
   * deferred set must be exactly the `ope`-indexed domains (no such v2 payload
   * can exist — EQL v2 scalars carry `hm`/`bf`/`ob`, never `op`) plus the one
   * `ste_vec` domain the shipped client refuses to write in v2 mode.
   */
  it('defers exactly the domains its written reasons cover', () => {
    expect(plan.deferred.map((domain) => domain.eqlType).sort()).toEqual(
      [...v2OpeIndexedDomains(), 'public.eql_v3_json_search'].sort(),
    )
  })

  /**
   * Deferring a domain is normally free — decrypt reconstructs from `cast_as`,
   * and every deferred domain shares its `cast_as` with a covered one. Deferring
   * the LAST domain on an axis is not free, and would otherwise be invisible:
   * the integration suite would still show ~100 green cases.
   */
  it('loses no plaintext axis to a deferral without declaring it', () => {
    expect(v2UndeclaredCastAs(plan)).toEqual([])
    // Pinned, not derived: the axes the v2 READ path is actually proven on.
    // `json` is absent and declared unreachable — no v2 ste_vec fixture can be
    // minted with cipherstash-client 0.42.
    expect(
      [...new Set(plan.cases.map((fixture) => fixture.castAs))].sort(),
    ).toEqual(['bigint', 'boolean', 'date', 'number', 'string', 'timestamp'])
  })
})
